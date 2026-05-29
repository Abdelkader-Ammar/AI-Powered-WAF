package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"trustscore"
	"trustscore/middleware"
)

type WafConfig struct {
	Threshold       float64 `json:"threshold"`
	StricterMargin  float64 `json:"stricter_margin"` // margin below threshold for uncertain zone; default 0.2
	WeightIP        float64 `json:"weight_ip"`
	WeightUser      float64 `json:"weight_user"`
	WeightBoost     float64 `json:"weight_boost"`
	IdentityMode    string            `json:"identity_mode"` // "jwt", "headers", "opaque"
	JWTSecret       string            `json:"jwt_secret"`
	OpaqueURL       string            `json:"opaque_url"`
	AuthAPIFailOpen bool              `json:"auth_api_fail_open"`
	UseTLS          bool              `json:"use_tls"`
	CorazaRulesPath string            `json:"coraza_rules_path"`
	EnableCoraza    bool              `json:"enable_coraza"`
	TierAllowRate   float64           `json:"tier_allow_rate"`
	TierAllowBurst  float64           `json:"tier_allow_burst"`
	TierStricterRate   float64        `json:"tier_stricter_rate"`
	TierStricterBurst  float64        `json:"tier_stricter_burst"`
	TierChallengeRate  float64        `json:"tier_challenge_rate"`
	TierChallengeBurst float64        `json:"tier_challenge_burst"`
	Trustscore      trustscore.Config `json:"trustscore"`
	Tier1Config     trustscore.Tier1Config `json:"tier1_config"`
	EnableRASP      bool              `json:"enable_rasp"`       // Tier 2 ingest
	RASPSocketPath  string            `json:"rasp_socket_path"`  // unix socket for the agent
	TrustXForwardedFor bool           `json:"trust_xforwarded"`  // read client IP from XFF (behind a trusted LB only)
}

var (
	ConfigMu   sync.RWMutex
	LiveConfig WafConfig
)

func generateJWTSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("failed to generate JWT secret: %v", err)
	}
	return hex.EncodeToString(b)
}

func loadOrGenerateJWTSecret(configDir string) string {
	secretPath := filepath.Join(configDir, ".jwt_secret")

	if data, err := os.ReadFile(secretPath); err == nil && len(data) > 0 {
		return string(data)
	}

	secret := generateJWTSecret()
	if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		log.Fatalf("failed to persist JWT secret: %v", err)
	}
	log.Printf("[INFO] Generated new JWT secret at %s", secretPath)
	return secret
}

func defaultConfig(threshold float64, configDir string) WafConfig {
	return WafConfig{
		Threshold:       threshold,
		StricterMargin:  0.2,
		WeightIP:        0.40,
		WeightUser:      0.60,
		WeightBoost:     0.30,
		IdentityMode:    "jwt",
		JWTSecret:       loadOrGenerateJWTSecret(configDir),
		OpaqueURL:       "http://localhost:8080/auth/verify",
		AuthAPIFailOpen: true,
		UseTLS:          false,
		CorazaRulesPath:     "crs",
		EnableCoraza:        true,
		TierAllowRate:       100,
		TierAllowBurst:      150,
		TierStricterRate:    30,
		TierStricterBurst:   50,
		TierChallengeRate:   10,
		TierChallengeBurst:  20,
		Trustscore:          trustscore.GetConfig(),
		Tier1Config: trustscore.Tier1Config{
			Enabled:             true,
			ModelURL:            "http://localhost:5001",
			ModelAPIKey:         "",
			ConfidenceThreshold: 0.85,
			WorkerCount:         3,
			MaxRetries:          3,
			CorrectionDelta:     0.20,
			GreyZones: map[string]trustscore.Tier1GreyZone{
				"allow":          {Center: 0.15, Width: 0.10},
				"allow+stricter": {Center: 0.40, Width: 0.15},
				"challenge":      {Center: 0.65, Width: 0.15},
				"block":          {Center: 0.85, Width: 0.10},
				"ban":            {Center: 0.95, Width: 0.05},
			},
			RedisQueueKey:     "tier1:queue",
			RedisFailedKey:    "tier1:failed",
			RedisResultPrefix: "tier1:result",
			AuditDBPath:       "./tier1_audit.db",
		},
		EnableRASP:     false, // opt-in: requires the RASP agent in/at the backend
		RASPSocketPath: "/run/waf-rasp.sock",
		TrustXForwardedFor: false, // opt-in: only safe behind a trusted proxy/LB
	}
}

func LoadWafConfig(filePath string, defaultThreshold float64) {
	ConfigMu.Lock()
	defer ConfigMu.Unlock()

	data, err := os.ReadFile(filePath)
	configDir := filepath.Dir(filePath)
	if err == nil {
		if err := json.Unmarshal(data, &LiveConfig); err != nil {
			log.Printf("[ERROR] Failed to parse config file %s: %v. Falling back to defaults.", filePath, err)
			LiveConfig = defaultConfig(defaultThreshold, configDir)
		}
	} else {
		log.Printf("[WARN] No config file found at %s, using defaults.", filePath)
		LiveConfig = defaultConfig(defaultThreshold, configDir)
	}
	trustscore.SetUserWeights(LiveConfig.WeightIP, LiveConfig.WeightUser, LiveConfig.WeightBoost)
	trustscore.SetConfig(LiveConfig.Trustscore)
}

func SaveWafConfig(filePath string, newConfig WafConfig, proxy *WAFProxy) error {
	ConfigMu.Lock()
	defer ConfigMu.Unlock()

	LiveConfig = newConfig
	data, err := json.MarshalIndent(LiveConfig, "", "  ")
	if err != nil {
		return err
	}
	
	tmpFile := filePath + ".tmp"
	err = os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		return err
	}
	err = os.Rename(tmpFile, filePath)
	if err != nil {
		return err
	}

	// Update trustscore weights and config
	trustscore.SetUserWeights(LiveConfig.WeightIP, LiveConfig.WeightUser, LiveConfig.WeightBoost)
	trustscore.SetConfig(LiveConfig.Trustscore)

	// Update proxy threshold
	proxy.ThresholdMu.Lock()
	proxy.Threshold = LiveConfig.Threshold
	proxy.ThresholdMu.Unlock()

	// Update resolver
	var newResolver middleware.IdentityResolver
	switch LiveConfig.IdentityMode {
	case "headers":
		newResolver = middleware.NewHeaderResolver()
	case "opaque":
		newResolver = middleware.NewOpaqueResolver(LiveConfig.OpaqueURL, "header:Authorization", nil, LiveConfig.AuthAPIFailOpen)
	case "jwt":
		fallthrough
	default:
		newResolver = middleware.NewJWTResolver([]byte(LiveConfig.JWTSecret))
	}

	proxy.ResolverMu.Lock()
	proxy.Resolver = newResolver
	proxy.ResolverMu.Unlock()

	// Update Coraza WAF
	initCorazaWAF(proxy)

	return nil
}
