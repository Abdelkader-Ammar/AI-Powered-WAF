package main

import (
	"flag"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"

	"trustscore"
	"trustscore/middleware"
	"github.com/dmitryikh/leaves"
	"github.com/redis/go-redis/v9"
)

type LeavesModel struct {
	model *leaves.Ensemble
}

func (m *LeavesModel) PredictSingle(features []float64) float64 {
	// leaves returns the raw sum of trees for LightGBM
	// We must apply the sigmoid function to convert the raw margin to a probability
	margin := m.model.PredictSingle(features, 0)
	return 1.0 / (1.0 + math.Exp(-margin))
}

func main() {
	var (
		modelDir  string
		listen    string
		backend   string
		threshold float64
	)

	flag.StringVar(&modelDir, "model-dir", "model", "Directory containing LightGBM text model and TF-IDF JSON assets")
	flag.StringVar(&listen, "listen", ":8080", "Address to listen on")
	flag.StringVar(&backend, "backend", "http://localhost:9090", "Backend HTTP server to forward safe traffic to")
	flag.Float64Var(&threshold, "threshold", 0.90, "Malicious probability threshold for blocking (0.0 to 1.0)")
	flag.Parse()

	log.Printf("Starting AI WAF Proxy on %s...", listen)
	log.Printf("Backend target: %s", backend)
	log.Printf("Block threshold: %.4f", threshold)

	// 1. Load TF-IDF Vectorizer
	vocabPath := filepath.Join(modelDir, "tfidf_vocab.json")
	log.Printf("Loading TF-IDF vectorizer from %s...", vocabPath)
	vectorizer, err := LoadTfidf(vocabPath)
	if err != nil {
		log.Fatalf("Failed to load TF-IDF vectorizer: %v", err)
	}
	log.Printf("Loaded TF-IDF with %d features.", vectorizer.NumCols)

	// 2. Load LightGBM Model
	modelPath := filepath.Join(modelDir, "lightgbm_waf.txt")
	log.Printf("Loading LightGBM model from %s...", modelPath)
	model, err := leaves.LGEnsembleFromFile(modelPath, false)
	if err != nil {
		log.Fatalf("Failed to load LightGBM model: %v", err)
	}
	log.Printf("Model loaded successfully.")

	lgbModel := &LeavesModel{model: model}

	// 3. Load Dynamic Configuration (replaces static threshold and resolver)
	LoadWafConfig("waf_config.json", threshold)

	// Deployment overrides via env (handy for containers / the demo, no config
	// file edit needed). RASP is opt-in because it only does anything when the
	// agent is actually running in/under your backend; ENABLE_RASP=true turns on
	// ingest. TRUST_XFORWARDED=true makes the WAF read the client IP from
	// X-Forwarded-For — only safe behind a trusted load balancer.
	if os.Getenv("ENABLE_RASP") == "true" {
		LiveConfig.EnableRASP = true
	}
	if s := os.Getenv("RASP_SOCKET_PATH"); s != "" {
		LiveConfig.RASPSocketPath = s
	}
	if os.Getenv("TRUST_XFORWARDED") == "true" {
		LiveConfig.TrustXForwardedFor = true
	}
	// Demo can start with the signature/ML front tier permissive (Coraza off,
	// high ML threshold) to spotlight the RASP and UEBA layers; both stay live-
	// toggleable from the dashboard.
	if os.Getenv("ENABLE_CORAZA") == "false" {
		LiveConfig.EnableCoraza = false
	}

	var initialResolver middleware.IdentityResolver
	switch LiveConfig.IdentityMode {
	case "headers":
		initialResolver = middleware.NewHeaderResolver()
	case "opaque":
		initialResolver = middleware.NewOpaqueResolver(LiveConfig.OpaqueURL, "header:Authorization", nil, LiveConfig.AuthAPIFailOpen)
	case "jwt":
		fallthrough
	default:
		initialResolver = middleware.NewJWTResolver([]byte(LiveConfig.JWTSecret))
	}

	// 4. Initialize Proxy
	proxy, err := NewWAFProxy(backend, vectorizer, lgbModel, LiveConfig.Threshold, initialResolver)
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}

	// 5. Initialize rate limiters
	proxy.RateLimiter = NewRateLimiter()
	proxy.ChallengeLimiter = NewRateLimiter()
	proxy.ActiveLimiter = proxy.RateLimiter

	// 6. Initialize optional Coraza WAF
	initCorazaWAF(proxy)

	// 7. Initialize Redis client (shared across Tier 0 and Tier 1). Address is
	// configurable via REDIS_ADDR so the WAF can reach a Redis on another host
	// (e.g. in a container network); defaults to localhost:6379.
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	proxy.Redis = redisClient

	// Wire the trust engine's score exporter to the same Redis so ExportScore
	// actually publishes id->score (the Gatekeeper fast-path and the dashboard
	// live panel read it). Without this, ExportScore silently no-ops.
	trustscore.InitRedis(redisAddr, "", 0)

	// 8. Initialize Tier 1 pipeline
	if LiveConfig.Tier1Config.Enabled {
		tier1, err := trustscore.NewTier1Pipeline(LiveConfig.Tier1Config, redisClient)
		if err != nil {
			log.Printf("[WARN] Tier 1 pipeline unavailable: %v — continuing without it", err)
		} else {
			proxy.Tier1 = tier1
			tier1.Start()
			log.Printf("[INFO] Tier 1 pipeline started")
		}
	}

	// 9. Start RASP (Tier 2) ingest listener if enabled
	if LiveConfig.EnableRASP {
		if err := trustscore.StartRASPIngest(LiveConfig.RASPSocketPath); err != nil {
			log.Printf("[WARN] RASP ingest disabled: %v", err)
		}
	}

	// 10. Start Admin Dashboard Server on port 8081
	startAdminServer(proxy)

	// 10. Start Main WAF Proxy Server
	server := &http.Server{
		Addr:    listen,
		Handler: proxy,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	// Graceful shutdown
	if proxy.Tier1 != nil {
		proxy.Tier1.Stop()
	}
	redisClient.Close()
}
