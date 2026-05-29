package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"trustscore"

	"golang.org/x/crypto/bcrypt"
)

type AdminStore struct {
	SessionSecret string            `json:"session_secret"`
	Admins        map[string]string `json:"admins"` // username -> bcrypt hash
}

var (
	adminStoreFile = "admins.json"
	adminMu        sync.RWMutex
	liveAdminStore AdminStore
)

func loadAdminStore() {
	adminMu.Lock()
	defer adminMu.Unlock()
	
	data, err := os.ReadFile(adminStoreFile)
	if err == nil {
		json.Unmarshal(data, &liveAdminStore)
	}

	if liveAdminStore.Admins == nil {
		liveAdminStore.Admins = make(map[string]string)
	}
	if liveAdminStore.SessionSecret == "" {
		sec := make([]byte, 32)
		rand.Read(sec)
		liveAdminStore.SessionSecret = hex.EncodeToString(sec)
		if err := saveAdminStoreLocked(); err != nil {
			log.Fatalf("failed to persist admin session secret: %v", err)
		}
	}
}

func saveAdminStoreLocked() error {
	data, err := json.MarshalIndent(liveAdminStore, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal admin store: %w", err)
	}
	if err := os.WriteFile(adminStoreFile, data, 0600); err != nil {
		return fmt.Errorf("write admin store to %s: %w", adminStoreFile, err)
	}
	return nil
}

func createAdmin(username, password string) error {
	adminMu.Lock()
	defer adminMu.Unlock()
	if _, exists := liveAdminStore.Admins[username]; exists {
		return fmt.Errorf("user exists")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	liveAdminStore.Admins[username] = string(hash)
	if err := saveAdminStoreLocked(); err != nil {
		return fmt.Errorf("failed to persist admin store: %w", err)
	}
	return nil
}

func verifyAdmin(username, password string) bool {
	adminMu.RLock()
	defer adminMu.RUnlock()
	hash, exists := liveAdminStore.Admins[username]
	if !exists {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func generateSessionCookie(username string) *http.Cookie {
	adminMu.RLock()
	secret := liveAdminStore.SessionSecret
	adminMu.RUnlock()

	exp := time.Now().Add(24 * time.Hour).Unix()
	msg := fmt.Sprintf("%s:%d", username, exp)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))

	return &http.Cookie{
		Name:     "admin_session",
		Value:    fmt.Sprintf("%s:%s", msg, sig),
		Path:     "/",
		HttpOnly: true,
		Secure:   LiveConfig.UseTLS, // only set on HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	}
}

func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return false
	}
	
	adminMu.RLock()
	secret := liveAdminStore.SessionSecret
	adminMu.RUnlock()

	msg := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	
	if hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		var exp int64
		fmt.Sscanf(parts[1], "%d", &exp)
		if time.Now().Unix() < exp {
			return true
		}
	}
	return false
}

func secureApiMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		if !validateSession(r) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func startAdminServer(proxy *WAFProxy) {
	loadAdminStore()

	mux := http.NewServeMux()
	
	apiMux := http.NewServeMux()

	apiMux.HandleFunc("/api/admin/status", func(w http.ResponseWriter, r *http.Request) {
		adminMu.RLock()
		setupRequired := len(liveAdminStore.Admins) == 0
		adminMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"setup_required": setupRequired})
	})

	apiMux.HandleFunc("/api/admin/setup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		adminMu.RLock()
		setupRequired := len(liveAdminStore.Admins) == 0
		adminMu.RUnlock()
		if !setupRequired {
			http.Error(w, "Setup already complete", http.StatusForbidden)
			return
		}

		var creds struct { Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}

		if err := createAdmin(creds.Username, creds.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		http.SetCookie(w, generateSessionCookie(creds.Username))
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	apiMux.HandleFunc("/api/admin/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var creds struct { Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		if verifyAdmin(creds.Username, creds.Password) {
			http.SetCookie(w, generateSessionCookie(creds.Username))
			json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	})

	// Protected Routes
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(LiveConfig)
		} else if r.Method == http.MethodPost {
			var newConfig WafConfig
			if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
				http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
				return
			}

			if err := SaveWafConfig("waf_config.json", newConfig, proxy); err != nil {
				http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	protectedMux.HandleFunc("/api/admin/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var creds struct { Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		if err := createAdmin(creds.Username, creds.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	// Reset every tunable value to its built-in default. The JWT secret (read
	// from disk by defaultConfig) and the admin accounts (separate store) are
	// preserved, so a reset does not log anyone out.
	protectedMux.HandleFunc("/api/admin/config/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		def := defaultConfig(0.90, ".")
		if err := SaveWafConfig("waf_config.json", def, proxy); err != nil {
			http.Error(w, "Failed to reset configuration", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
	})

	// Clear all runtime data (profiles, scores, decision & RASP feeds) but keep
	// admin accounts and configuration.
	protectedMux.HandleFunc("/api/admin/reset-data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		trustscore.ResetAllData()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
	})

	apiMux.Handle("/api/admin/config", secureApiMiddleware(protectedMux))
	apiMux.Handle("/api/admin/config/reset", secureApiMiddleware(protectedMux))
	apiMux.Handle("/api/admin/reset-data", secureApiMiddleware(protectedMux))
	apiMux.Handle("/api/admin/create", secureApiMiddleware(protectedMux))

	mux.Handle("/api/", apiMux)
	// The admin server exposes only the JSON config/control API; the operator UI
	// is served separately by the dashboard service. Root returns a health probe.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"service": "ai-waf admin api", "status": "ok"})
	})

	log.Printf("Starting Admin API Server on :8081...")
	go func() {
		if err := http.ListenAndServe(":8081", mux); err != nil {
			log.Fatalf("Admin server failed: %v", err)
		}
	}()
}
