package middleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"trustscore"
	"github.com/golang-jwt/jwt/v5"
)

type IdentityResolver interface {
	Resolve(r *http.Request) (*trustscore.IdentityContext, error)
}

// ---------------------------------------------------------
// JWT Resolver
// ---------------------------------------------------------

type JWTResolver struct {
	Secret       []byte
	TokenHeader  string
	UserIDClaim  string
	EmailClaim   string
	MFAClaim     string
	CreatedClaim string
}

func NewJWTResolver(secret []byte) *JWTResolver {
	return &JWTResolver{
		Secret:       secret,
		TokenHeader:  "Authorization",
		UserIDClaim:  "sub",
		EmailClaim:   "email_verified",
		MFAClaim:     "mfa_enabled",
		CreatedClaim: "account_created_at",
	}
}

func (j *JWTResolver) Resolve(r *http.Request) (*trustscore.IdentityContext, error) {
	auth := r.Header.Get(j.TokenHeader)
	if auth == "" {
		return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
	}
	tokenString := strings.TrimPrefix(auth, "Bearer ")

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return j.Secret, nil
	})

	if err != nil || !token.Valid {
		return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
	}

	ctx := &trustscore.IdentityContext{
		ResolvedBy: "jwt",
	}

	if sub, ok := claims[j.UserIDClaim].(string); ok {
		ctx.UserID = sub
	} else {
		return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
	}

	if email, ok := claims[j.EmailClaim].(bool); ok {
		ctx.EmailVerified = email
	}
	if mfa, ok := claims[j.MFAClaim].(bool); ok {
		ctx.MFAEnabled = mfa
	}
	if created, ok := claims["account_created_at"].(float64); ok {
		ctx.AccountCreatedAt = created
	} else if created, ok := claims["created_at"].(float64); ok {
		ctx.AccountCreatedAt = created
	}

	return ctx, nil
}

// ---------------------------------------------------------
// Header Resolver (Forward Auth)
// ---------------------------------------------------------

type HeaderResolver struct {
	UserIDHeader  string
	EmailHeader   string
	MFAHeader     string
	CreatedHeader string
}

func NewHeaderResolver() *HeaderResolver {
	return &HeaderResolver{
		UserIDHeader:  "X-User-ID",
		EmailHeader:   "X-Email-Verified",
		MFAHeader:     "X-MFA-Enabled",
		CreatedHeader: "X-Account-Created",
	}
}

func (h *HeaderResolver) Resolve(r *http.Request) (*trustscore.IdentityContext, error) {
	// SECURITY: Strip any client-injected identity headers before reading.
	// In a forward-auth deployment, the upstream auth proxy re-injects verified
	// headers after the WAF strips them. If the WAF is exposed directly, these
	// will be empty and the user resolves as anonymous (safe default).
	r.Header.Del("X-User-ID")
	r.Header.Del("X-Email-Verified")
	r.Header.Del("X-MFA-Enabled")
	r.Header.Del("X-Account-Created")

	userID := r.Header.Get(h.UserIDHeader)
	if userID == "" {
		return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
	}

	ctx := &trustscore.IdentityContext{
		UserID:     userID,
		ResolvedBy: "headers",
	}

	if r.Header.Get(h.EmailHeader) == "true" {
		ctx.EmailVerified = true
	}
	if r.Header.Get(h.MFAHeader) == "true" {
		ctx.MFAEnabled = true
	}
	if c, err := strconv.ParseFloat(r.Header.Get(h.CreatedHeader), 64); err == nil {
		ctx.AccountCreatedAt = c
	}

	return ctx, nil
}

// ---------------------------------------------------------
// Opaque Resolver (Auth API)
// ---------------------------------------------------------

type OpaqueResolver struct {
	URL         string
	TokenSource string // e.g. "cookie:session_id" or "header:Authorization"
	CacheTTL    time.Duration
	cache       map[string]cachedIdentity
	cacheMu     sync.RWMutex
	cacheKey    []byte
	failOpen    bool
}

type cachedIdentity struct {
	ctx       *trustscore.IdentityContext
	expiresAt time.Time
}

func NewOpaqueResolver(url, tokenSource string, cacheKey []byte, failOpen bool) *OpaqueResolver {
	if len(cacheKey) == 0 {
		cacheKey = make([]byte, 32)
		if _, err := rand.Read(cacheKey); err != nil {
			log.Fatalf("failed to generate opaque cache key: %v", err)
		}
	}

	o := &OpaqueResolver{
		URL:         url,
		TokenSource: tokenSource,
		CacheTTL:    5 * time.Minute,
		cache:       make(map[string]cachedIdentity),
		cacheKey:    cacheKey,
		failOpen:    failOpen,
	}

	go func() {
		for {
			time.Sleep(10 * time.Minute)
			now := time.Now()
			o.cacheMu.Lock()
			for k, v := range o.cache {
				if now.After(v.expiresAt) {
					delete(o.cache, k)
				}
			}
			o.cacheMu.Unlock()
		}
	}()

	return o
}

func (o *OpaqueResolver) Resolve(r *http.Request) (*trustscore.IdentityContext, error) {
	var token string
	parts := strings.SplitN(o.TokenSource, ":", 2)
	if len(parts) == 2 {
		if parts[0] == "cookie" {
			if c, err := r.Cookie(parts[1]); err == nil {
				token = c.Value
			}
		} else if parts[0] == "header" {
			token = r.Header.Get(parts[1])
			token = strings.TrimPrefix(token, "Bearer ")
		}
	}

	if token == "" {
		return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
	}

	// HMAC hash token for cache key using the generated secret
	mac := hmac.New(sha256.New, o.cacheKey)
	mac.Write([]byte(token))
	cacheKey := hex.EncodeToString(mac.Sum(nil))

	o.cacheMu.RLock()
	if cached, ok := o.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		o.cacheMu.RUnlock()
		return cached.ctx, nil
	}
	o.cacheMu.RUnlock()

	// Cache miss - call API with timeout
	type opaqueAuthRequest struct {
		Token string `json:"token"`
	}

	body, err := json.Marshal(opaqueAuthRequest{Token: token})
	if err != nil {
		return nil, fmt.Errorf("marshal auth request: %w", err)
	}

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxTimeout, "POST", o.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// SECURITY: Never log 'body' or 'token'. Only log the URL and error type.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Fail-open behavior: if the auth API is unreachable or times out, treat the request
		// as anonymous (IP-only scoring). This prevents auth service outages from causing
		// total application downtime, at the cost of reduced scoring precision.
		//
		// SECURITY TRADEOFF: An attacker who DDoSes the auth API can degrade legitimate
		// authenticated users to anonymous scoring, removing their trust boosters
		// (email_verified, MFA, account_age). Both legitimate users and attackers are
		// then scored by IP behavior only. If the attacker controls clean IPs, they may
		// pass through more easily during the outage.
		//
		// Mitigation: Monitor auth API health independently. Set AuthAPIFailOpen=false
		// (fail-closed, return 503) for high-sensitivity endpoints if availability tradeoff
		// is unacceptable. Default is true to maximize availability.
		if o.failOpen {
			return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
		}
		return nil, fmt.Errorf("auth API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if o.failOpen {
			return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
		}
		return nil, fmt.Errorf("auth API returned %d", resp.StatusCode)
	}

	var apiResp struct {
		UserID           string  `json:"user_id"`
		EmailVerified    bool    `json:"email_verified"`
		MFAEnabled       bool    `json:"mfa_enabled"`
		AccountCreatedAt float64 `json:"account_created_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		if o.failOpen {
			return &trustscore.IdentityContext{ResolvedBy: "anonymous"}, nil
		}
		return nil, fmt.Errorf("decode auth response: %w", err)
	}

	ctx := &trustscore.IdentityContext{
		UserID:           apiResp.UserID,
		EmailVerified:    apiResp.EmailVerified,
		MFAEnabled:       apiResp.MFAEnabled,
		AccountCreatedAt: apiResp.AccountCreatedAt,
		ResolvedBy:       "auth_api",
	}

	o.cacheMu.Lock()
	o.cache[cacheKey] = cachedIdentity{
		ctx:       ctx,
		expiresAt: time.Now().Add(o.CacheTTL),
	}
	o.cacheMu.Unlock()

	return ctx, nil
}
