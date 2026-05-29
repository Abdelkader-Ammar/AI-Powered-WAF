package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"trustscore"
	"trustscore/middleware"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func truncate(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

// Model interface represents our ML predictor
type Model interface {
	PredictSingle(features []float64) float64
}

// WAFProxy encapsulates the WAF logic and reverse proxy
type WAFProxy struct {
	BackendURL       *url.URL
	Proxy            *httputil.ReverseProxy
	Vectorizer       *TfidfVectorizer
	Model            Model
	ThresholdMu      sync.RWMutex
	Threshold        float64
	ResolverMu       sync.RWMutex
	Resolver         middleware.IdentityResolver
	Coraza           *CorazaWAF
	RateLimiter      *RateLimiter
	ChallengeLimiter *RateLimiter
	ActiveLimiter    RateLimiterBackend
	Tier1            *trustscore.Tier1Pipeline
	Redis            *redis.Client
}

// NewWAFProxy creates a new WAFProxy
func NewWAFProxy(backend string, vectorizer *TfidfVectorizer, model Model, threshold float64, resolver middleware.IdentityResolver) (*WAFProxy, error) {
	parsedURL, err := url.Parse(backend)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	return &WAFProxy{
		BackendURL: parsedURL,
		Proxy:      proxy,
		Vectorizer: vectorizer,
		Model:      model,
		Threshold:  threshold,
		Resolver:   resolver,
	}, nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int64
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.size += int64(n)
	return n, err
}

func verifyChallengeCookie(r *http.Request, clientIP string) bool {
	secret := []byte(LiveConfig.JWTSecret)
	if len(secret) == 0 {
		return false
	}

	cookie, err := r.Cookie("waf_clearance")
	if err != nil {
		return false
	}

	salt, _, valid := verifyClearanceToken(cookie.Value, secret)
	if !valid {
		return false
	}

	// Extract IP from salt (format: "IP:YYYY-MM-DD")
	lastColon := strings.LastIndex(salt, ":")
	if lastColon < 0 {
		return false
	}
	saltIP := salt[:lastColon]

	// Exact IP match
	if saltIP == clientIP {
		return true
	}
	// IPv4 /24 fallback for mobile / flaky connections
	if ip24 := ipv4Mask24(clientIP); ip24 != "" && saltIP == ip24 {
		return true
	}
	// IPv6 /64 fallback
	if ip64 := ipv6Mask64(clientIP); ip64 != "" && saltIP == ip64 {
		return true
	}

	return false
}

func getClientIP(r *http.Request) string {
	// Behind a trusted load balancer, the real client IP is in X-Forwarded-For.
	// Only honoured when explicitly enabled (a client could otherwise spoof it).
	if LiveConfig.TrustXForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

func (wp *WAFProxy) checkRateLimits(w http.ResponseWriter, r *http.Request, clientIP string, identity *trustscore.IdentityContext, tier string, start time.Time, challengeBypassed bool, sessionID string) (bool, string) {
	var rate, burst float64
	switch tier {
	case "allow":
		rate, burst = LiveConfig.TierAllowRate, LiveConfig.TierAllowBurst
	case "allow+stricter":
		rate, burst = LiveConfig.TierStricterRate, LiveConfig.TierStricterBurst
	case "challenge":
		rate, burst = LiveConfig.TierChallengeRate, LiveConfig.TierChallengeBurst
	default:
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false, "unknown_tier"
	}

	retryAfter := int(math.Ceil(1.0 / rate))

	allowed, backendOK := wp.ActiveLimiter.AllowIP(clientIP, rate, burst)
		if !backendOK {
			allowed, _ = wp.RateLimiter.AllowIP(clientIP, rate, burst)
		}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.Header().Set("X-RateLimit-Limit", strconv.FormatFloat(burst, 'f', 0, 64))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Duration(retryAfter)*time.Second).Unix(), 10))
		http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
		wp.fireTelemetry(r, clientIP, identity, start, challengeBypassed, sessionID, tier, "ip")
		return false, "rate_limit_ip"
	}

	if identity.UserID != "" {
		allowed, backendOK = wp.ActiveLimiter.AllowUser(identity.UserID, rate, burst)
		if !backendOK {
			allowed, _ = wp.RateLimiter.AllowUser(identity.UserID, rate, burst)
		}
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.Header().Set("X-RateLimit-Limit", strconv.FormatFloat(burst, 'f', 0, 64))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Duration(retryAfter)*time.Second).Unix(), 10))
			http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
			wp.fireTelemetry(r, clientIP, identity, start, challengeBypassed, sessionID, tier, "user")
			return false, "rate_limit_user"
		}
	}

	return true, ""
}

func verifyNonce(nonce, expectedSalt string) bool {
	hash := sha256.Sum256([]byte(expectedSalt + nonce))
	return strings.HasPrefix(hex.EncodeToString(hash[:]), "00000")
}

func (wp *WAFProxy) handleChallengeSolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	// Resolve identity for telemetry
	wp.ResolverMu.RLock()
	identity, err := wp.Resolver.Resolve(r)
	wp.ResolverMu.RUnlock()
	if err != nil {
		identity = &trustscore.IdentityContext{ResolvedBy: "anonymous"}
	}

	// Dedicated challenge limit: 10 attempts per IP per minute
	challengeRate := 10.0 / 60.0
	challengeBurst := 10.0
	if ok, _ := wp.ChallengeLimiter.AllowIP(clientIP, challengeRate, challengeBurst); !ok {
		retryAfter := int(math.Ceil(1.0 / challengeRate))
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		http.Error(w, "Too Many Challenge Attempts", http.StatusTooManyRequests)
		return
	}

	salt := fmt.Sprintf("%s:%s", clientIP, time.Now().Format("2006-01-02"))

	var req struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if !verifyNonce(req.Nonce, salt) {
		http.Error(w, "Invalid nonce", http.StatusUnauthorized)
		return
	}

	secret := []byte(LiveConfig.JWTSecret)
	token := generateClearanceToken(salt, req.Nonce, secret)

	http.SetCookie(w, &http.Cookie{
		Name:     "waf_clearance",
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   3600,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})

	trustscore.RecordChallengeSolved(clientIP, identity.UserID, float64(time.Now().Unix()))
}

func extractSessionID(r *http.Request, clientIP string) string {
	if c, err := r.Cookie("session_id"); err == nil && c.Value != "" {
		return c.Value
	}
	if c, err := r.Cookie("waf_session"); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("X-Session-ID"); h != "" {
		return h
	}
	h := sha256.Sum256([]byte(clientIP + ":" + r.UserAgent()))
	return fmt.Sprintf("%x", h)[:16]
}

func buildRawEvent(r *http.Request, ip string, start time.Time, statusCode int, bodyBytes []byte, challengePassed bool, sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"ip":              ip,
		"session_id":      sessionID,
		"timestamp":       float64(start.Unix()),
		"method":          r.Method,
		"path":            r.URL.Path,
		"query_string":    r.URL.RawQuery,
		"status_code":     float64(statusCode),
		"response_size":   float64(len(bodyBytes)), // Approx if accurate not provided
		"request_size":    float64(len(bodyBytes)),
		"content_type":    r.Header.Get("Content-Type"),
		"user_agent":      r.UserAgent(),
		"referer":         r.Referer(),
		"accept":          r.Header.Get("Accept"),
		"accept_language": r.Header.Get("Accept-Language"),
		"ja4_fingerprint": r.Header.Get("JA4"), // Assuming proxy/cloudflare sets this
		"challenge_passed": challengePassed,
	}
}

func (wp *WAFProxy) fireTelemetry(r *http.Request, clientIP string, identity *trustscore.IdentityContext, start time.Time, challengeBypassed bool, sessionID string, tier string, limitType string) {
	rawEvent := buildRawEvent(r, clientIP, start, http.StatusTooManyRequests, nil, challengeBypassed, sessionID)
	rawEvent["rate_limit_hit"] = true
	rawEvent["rate_limit_tier"] = tier
	rawEvent["rate_limit_type"] = limitType
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC] rate limit telemetry: %v", rec)
			}
		}()
		if identity.UserID != "" {
			trustscore.ProcessEventForUser(identity, rawEvent)
		} else {
			trustscore.ProcessEvent(rawEvent)
		}
	}()
}

func (wp *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/challenge-solve" {
		wp.handleChallengeSolve(w, r)
		return
	}

	start := time.Now()

	reqLog := map[string]interface{}{
		"timestamp":      start.Format(time.RFC3339),
		"method":         r.Method,
		"path":           r.URL.Path,
		"query":          r.URL.RawQuery, // the payload in the query string
		"body":           "",             // populated below once the body is read
		"ip":             "",
		"user_id":        "",
		"trust_score":    0.0,
		"lgbm_prob":      0.0,
		"coraza_verdict": "",
		"response_code":  0,
		"decision":       "",
	}

	writeLog := func(status int, decision string) {
		reqLog["response_code"] = status
		reqLog["decision"] = decision
		logBytes, _ := json.Marshal(reqLog)
		log.Println("[ACCESS_LOG]", string(logBytes))
		// Publish a capped recent-events feed for the dashboard so it can show
		// exactly what was decided per request and why (decision string, lgbm
		// probability, coraza verdict, trust score, request id).
		if wp.Redis != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			wp.Redis.LPush(ctx, "waf:events", logBytes)
			wp.Redis.LTrim(ctx, "waf:events", 0, 199)
			cancel()
		}
	}

	// 1. Resolve Identity
	wp.ResolverMu.RLock()
	identity, err := wp.Resolver.Resolve(r)
	wp.ResolverMu.RUnlock()
	if err != nil {
		identity = &trustscore.IdentityContext{ResolvedBy: "anonymous"}
	}

	clientIP := getClientIP(r)
	reqLog["ip"] = clientIP
	if identity.UserID != "" {
		reqLog["user_id"] = identity.UserID
	}

	// 2. Extract session ID from cookie, header, or deterministic fallback
	sessionID := extractSessionID(r, clientIP)

	// 3. Read the body (up to 1MB) for both feature extraction and event size
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			log.Printf("[ERROR] Failed to read request body: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		reqLog["body"] = truncate(string(bodyBytes), 300) // payload snippet for the dashboard
	}

	fireAsyncLearner := func(statusCode int, responseSize int64, chPassed bool) {
		reqClone := r.Clone(r.Context()) // safe to capture
		go func(req *http.Request, id *trustscore.IdentityContext, ip string, st time.Time, status int, bBytes []byte, respSz int64, passed bool) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC] Async learner recovered: %v", rec)
			}
		}()
			rawEvent := buildRawEvent(req, ip, st, status, bBytes, passed, sessionID)
			rawEvent["response_size"] = float64(respSz)
			if id.UserID != "" {
				trustscore.ProcessEventForUser(id, rawEvent)
			} else {
				trustscore.ProcessEvent(rawEvent)
			}
		}(reqClone, identity, clientIP, start, statusCode, bodyBytes, responseSize, chPassed)
	}

	// 3. Gatekeeper Check (Sync)
	verdict := trustscore.Gatekeeper(clientIP, identity.UserID, float64(start.Unix()))
	// Log the score that actually governs this entity: the user score when
	// authenticated, otherwise the IP score (UserScore is -1 for anonymous).
	if verdict.UserScore >= 0 {
		reqLog["trust_score"] = verdict.UserScore
	} else {
		reqLog["trust_score"] = verdict.IPScore
	}

	challengeBypassed := verifyChallengeCookie(r, clientIP)

	switch verdict.Recommended {
	case "ban", "block":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":    "Forbidden by UEBA Gatekeeper",
			"decision": verdict.Recommended,
		})
		fireAsyncLearner(http.StatusForbidden, 0, false)
		writeLog(http.StatusForbidden, verdict.Recommended)
		return

	case "challenge":
		if !challengeBypassed {
			expectedSalt := fmt.Sprintf("%s:%s", clientIP, time.Now().Format("2006-01-02"))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Security Check</title>
<style>
  body { font-family: sans-serif; text-align: center; padding: 50px; background: #f9f9f9; }
  .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
  @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
</style>
</head>
<body>
  <h2>Checking your browser before accessing the site...</h2>
  <div class="loader"></div>
  <p>Please allow up to 5 seconds.</p>
  <script>
    async function solve() {
      const salt = "%s";
      const target = "00000";
      const encoder = new TextEncoder();
      let nonce = 0;
      while (true) {
        const data = encoder.encode(salt + nonce);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        if (hashHex.startsWith(target)) {
          const resp = await fetch('/challenge-solve', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({nonce: nonce.toString()})
          });
          if (resp.ok) {
            window.location.reload();
          }
          return;
        }
        nonce++;
        if (nonce %% 500 === 0) {
           await new Promise(r => setTimeout(r, 0));
        }
      }
    }
    solve();
  </script>
</body>
</html>`, expectedSalt)
			w.Write([]byte(html))
			fireAsyncLearner(http.StatusUnauthorized, int64(len(html)), false)
			writeLog(http.StatusUnauthorized, "challenge")
			return
		}
		// Challenge passed — check rate limits as allow+stricter
		if ok, reason := wp.checkRateLimits(w, r, clientIP, identity, "allow+stricter", start, challengeBypassed, sessionID); !ok {
			writeLog(http.StatusTooManyRequests, reason)
			return
		}

		// Challenge passed — treat as allow+stricter: run Coraza
		if wp.Coraza != nil && LiveConfig.EnableCoraza {
			allowed, _, err := wp.Coraza.ProcessRequest(r)
			if err != nil || !allowed {
				fireAsyncLearner(http.StatusForbidden, 0, challengeBypassed)
				writeLog(http.StatusForbidden, "block_coraza")
				return
			}
		}

	case "allow+stricter":
		if ok, reason := wp.checkRateLimits(w, r, clientIP, identity, "allow+stricter", start, challengeBypassed, sessionID); !ok {
			writeLog(http.StatusTooManyRequests, reason)
			return
		}

		// Always run Coraza for the stricter tier
		if wp.Coraza != nil && LiveConfig.EnableCoraza {
			allowed, _, err := wp.Coraza.ProcessRequest(r)
			if err != nil || !allowed {
				fireAsyncLearner(http.StatusForbidden, 0, challengeBypassed)
				writeLog(http.StatusForbidden, "block_coraza")
				return
			}
		}

	case "allow":
		if ok, reason := wp.checkRateLimits(w, r, clientIP, identity, "allow", start, challengeBypassed, sessionID); !ok {
			writeLog(http.StatusTooManyRequests, reason)
			return
		}
	}

	// 4. ML Feature Extraction (Only if Gatekeeper allowed)
	engFeatures := ExtractFeatures(r, bodyBytes)
	payloadText := truncate(r.URL.Path, 1024) + " " + truncate(r.URL.RawQuery, 1024) + " " + truncate(string(bodyBytes), 1024)
	tfidfFeatures := wp.Vectorizer.Transform(payloadText)

	totalFeatures := len(engFeatures) + len(tfidfFeatures)
	finalVector := make([]float64, 0, totalFeatures)
	finalVector = append(finalVector, engFeatures...)
	finalVector = append(finalVector, tfidfFeatures...)

	// 5. LightGBM Predict
	prob := wp.Model.PredictSingle(finalVector)
	reqLog["lgbm_prob"] = prob
	
	wp.ThresholdMu.RLock()
	currentThreshold := wp.Threshold
	wp.ThresholdMu.RUnlock()
	
	log.Printf("Request: %s %s | Gatekeeper: %s | LGBM Prob: %.4f | Latency: %v", r.Method, r.URL.Path, verdict.Recommended, prob, time.Since(start))

	// Tier 1: enqueue if LGBM prob falls in this tier's grey zone
	if wp.Tier1 != nil && wp.Tier1.Enabled() {
		greyZone, ok := LiveConfig.Tier1Config.GreyZones[verdict.Recommended]
		if ok && greyZone.Contains(prob) {
			job := trustscore.Tier1Job{
				ID: uuid.New().String(),
				Event: trustscore.RequestEvent{
					IP:              clientIP,
					SessionID:       sessionID,
					Timestamp:       float64(start.Unix()),
					Method:          r.Method,
					Path:            r.URL.Path,
					QueryString:     r.URL.RawQuery,
					ContentType:     r.Header.Get("Content-Type"),
					UserAgent:       r.UserAgent(),
					Referer:         r.Referer(),
					Accept:          r.Header.Get("Accept"),
					AcceptLanguage:  r.Header.Get("Accept-Language"),
					JA4Fingerprint:  r.Header.Get("JA4"),
					ChallengePassed: challengeBypassed,
				},
				LGBMProb:      prob,
				Tier0Decision: verdict.Recommended,
				ClientIP:      clientIP,
				UserID:        identity.UserID,
				BodySnippet:   string(bodyBytes[:min(len(bodyBytes), 1024)]),
				GreyZone:      greyZone,
				EnqueuedAt:    float64(time.Now().Unix()),
				Retries:       0,
			}
			if err := wp.Tier1.Enqueue(job); err != nil {
				log.Printf("[ERROR] Tier1 enqueue failed: %v", err)
			}
		}
	}

	if prob >= currentThreshold {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		resp := map[string]interface{}{
			"error": "Forbidden by AI WAF",
			"score": prob,
		}
		json.NewEncoder(w).Encode(resp)
		fireAsyncLearner(http.StatusForbidden, 0, challengeBypassed)
		writeLog(http.StatusForbidden, "block_lgbm")
		return
	}

	// Uncertain band: [threshold*(1-StricterMargin), threshold). StricterMargin
	// is admin-configurable (default 0.2), replacing the former hardcoded 0.8.
	uncertainLower := currentThreshold * (1.0 - LiveConfig.StricterMargin)
	if prob >= uncertainLower && prob < currentThreshold {
		// Uncertain LGBM — run Coraza if available (not already checked in switch)
		if wp.Coraza != nil && LiveConfig.EnableCoraza {
			allowed, _, err := wp.Coraza.ProcessRequest(r)
			if err != nil || !allowed {
				fireAsyncLearner(http.StatusForbidden, 0, challengeBypassed)
				writeLog(http.StatusForbidden, "block_coraza")
				return
			}
		}
		log.Printf("LightGBM uncertain: prob=%.4f within stricter margin.", prob)
	} else {
		log.Printf("LightGBM allow: prob=%.4f below stricter margin.", prob)
	}

	// 6. Reconstruct body and forward to backend
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
	} else {
		r.Body = io.NopCloser(bytes.NewReader([]byte{}))
		r.ContentLength = 0
	}
	r.Header.Del("X-WAF-Score")

	// 7. Inject RASP correlation headers so the agent in the backend can attribute
	// each syscall / DB query to this IP / user. SECURITY: strip any client-supplied
	// X-WAF-* first — the RASP trusts these for attribution, so a spoof must never
	// reach the backend.
	r.Header.Del("X-WAF-Request-ID")
	r.Header.Del("X-WAF-IP")
	r.Header.Del("X-WAF-User")
	requestID := uuid.New().String()
	r.Header.Set("X-WAF-Request-ID", requestID)
	r.Header.Set("X-WAF-IP", clientIP)
	if identity.UserID != "" {
		r.Header.Set("X-WAF-User", identity.UserID)
	}
	reqLog["request_id"] = requestID

	// 8. Proxy with status recorder to fire learner after response
	recorder := &statusRecorder{ResponseWriter: w, status: 200, size: 0}
	wp.Proxy.ServeHTTP(recorder, r)

	fireAsyncLearner(recorder.status, recorder.size, challengeBypassed)
	writeLog(recorder.status, "allow")
}
