package trustscore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRoBERTaClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-secret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		switch r.URL.Path {
		case "/predict":
			var req PredictRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			resp := PredictResponse{
				Label:         "benign",
				Confidence:    0.91,
				BenignProb:    0.91,
				MaliciousProb: 0.09,
			}
			json.NewEncoder(w).Encode(resp)

		case "/health":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewRoBERTaClient(server.URL, "test-secret")

	t.Run("HealthCheck", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.HealthCheck(ctx); err != nil {
			t.Fatalf("HealthCheck failed: %v", err)
		}
	})

	t.Run("PredictSuccess", func(t *testing.T) {
		job := Tier1Job{
			ID:            "test-job",
			Event:         RequestEvent{Method: "POST", Path: "/api/login", UserAgent: "test"},
			LGBMProb:      0.45,
			Tier0Decision: "challenge",
			ClientIP:      "192.168.1.100",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		result, err := client.Predict(ctx, job)
		if err != nil {
			t.Fatalf("Predict failed: %v", err)
		}
		if result.Label != "benign" {
			t.Errorf("expected label benign, got %s", result.Label)
		}
		if result.Confidence != 0.91 {
			t.Errorf("expected confidence 0.91, got %f", result.Confidence)
		}
	})

	t.Run("PredictInvalidLabel", func(t *testing.T) {
		badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(PredictResponse{Label: "unknown", Confidence: 0.5})
		}))
		defer badServer.Close()

		badClient := NewRoBERTaClient(badServer.URL, "")
		job := Tier1Job{ID: "bad", Event: RequestEvent{Method: "GET", Path: "/"}}
		_, err := badClient.Predict(context.Background(), job)
		if err == nil {
			t.Fatal("expected error for invalid label, got nil")
		}
	})

	t.Run("PredictInvalidConfidence", func(t *testing.T) {
		badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(PredictResponse{Label: "benign", Confidence: 1.5})
		}))
		defer badServer.Close()

		badClient := NewRoBERTaClient(badServer.URL, "")
		job := Tier1Job{ID: "bad", Event: RequestEvent{Method: "GET", Path: "/"}}
		_, err := badClient.Predict(context.Background(), job)
		if err == nil {
			t.Fatal("expected error for invalid confidence, got nil")
		}
	})

	t.Run("PredictServerError", func(t *testing.T) {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("GPU OOM"))
		}))
		defer errServer.Close()

		errClient := NewRoBERTaClient(errServer.URL, "")
		job := Tier1Job{ID: "err", Event: RequestEvent{Method: "GET", Path: "/"}}
		_, err := errClient.Predict(context.Background(), job)
		if err == nil {
			t.Fatal("expected error for 500 response, got nil")
		}
	})

	t.Run("PredictMissingAPIKey", func(t *testing.T) {
		noKeyClient := NewRoBERTaClient(server.URL, "")
		job := Tier1Job{ID: "nokey", Event: RequestEvent{Method: "GET", Path: "/"}}
		_, err := noKeyClient.Predict(context.Background(), job)
		if err == nil {
			t.Fatal("expected error for missing API key, got nil")
		}
	})
}
