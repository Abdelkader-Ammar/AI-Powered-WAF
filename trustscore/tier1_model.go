package trustscore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RoBERTaClient talks to the Python inference service.
type RoBERTaClient struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

// PredictRequest is what we send to the model.
type PredictRequest struct {
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers"`
	BodySnippet   string            `json:"body_snippet"`
	Tier0Decision string            `json:"tier0_decision"`
	LGBMProb      float64           `json:"lgbm_prob"`
}

// PredictResponse is what the model returns.
type PredictResponse struct {
	Label         string  `json:"label"`
	Confidence    float64 `json:"confidence"`
	BenignProb    float64 `json:"benign_prob"`
	MaliciousProb float64 `json:"malicious_prob"`
}

// NewRoBERTaClient creates a client. apiKey may be empty if auth is disabled.
func NewRoBERTaClient(baseURL, apiKey string) *RoBERTaClient {
	return &RoBERTaClient{
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

// Predict sends a request to the RoBERTa service.
func (c *RoBERTaClient) Predict(ctx context.Context, job Tier1Job) (*PredictResponse, error) {
	headers := buildHeadersMap(&job.Event)

	url := job.Event.Path
	if job.Event.QueryString != "" {
		url += "?" + job.Event.QueryString
	}

	reqBody := PredictRequest{
		Method:        job.Event.Method,
		URL:           url,
		Headers:       headers,
		BodySnippet:   job.BodySnippet,
		Tier0Decision: job.Tier0Decision,
		LGBMProb:      job.LGBMProb,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/predict", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("roberta returned %d: %s", resp.StatusCode, string(body))
	}

	var result PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Label != "benign" && result.Label != "malicious" {
		return nil, fmt.Errorf("invalid label: %s", result.Label)
	}
	if result.Confidence < 0 || result.Confidence > 1 {
		return nil, fmt.Errorf("invalid confidence: %f", result.Confidence)
	}

	return &result, nil
}

// HealthCheck verifies the model service is alive.
func (c *RoBERTaClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: %d", resp.StatusCode)
	}
	return nil
}

// buildHeadersMap constructs a headers map from the RequestEvent scalar fields.
func buildHeadersMap(event *RequestEvent) map[string]string {
	h := make(map[string]string)
	if event.ContentType != "" {
		h["Content-Type"] = event.ContentType
	}
	if event.UserAgent != "" {
		h["User-Agent"] = event.UserAgent
	}
	if event.Referer != "" {
		h["Referer"] = event.Referer
	}
	if event.Accept != "" {
		h["Accept"] = event.Accept
	}
	if event.AcceptLanguage != "" {
		h["Accept-Language"] = event.AcceptLanguage
	}
	return h
}
