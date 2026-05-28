package trustscore

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

func TestTimeWindow(t *testing.T) {
	now := 100.0
	timestamps := []float64{100, 99, 98, 97, 96}

	count := slidingWindowCount(timestamps, 5, now)
	if count != 5 {
		t.Errorf("Expected count 5, got %d", count)
	}

	rate := slidingWindowRate(timestamps, 5, now)
	if math.Abs(rate-1.0) > 0.01 {
		t.Errorf("Expected rate ~1.0, got %f", rate)
	}

	mean, _ := interArrivalStats(timestamps)
	if mean != 1.0 {
		t.Errorf("Expected mean 1.0, got %f", mean)
	}

	cv := coefficientOfVariation(timestamps)
	if cv != 0 {
		t.Errorf("Expected CV 0.0 (perfect intervals), got %f", cv)
	}
}

func TestHighRate404Detection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.TotalRequests = 100
	profile.Total404 = 60

	cfg := GetConfig()

	event := &RequestEvent{
		IP:        "192.168.1.1",
		Path:      "/about",
		Timestamp: 1000,
	}

	penalty, reasons, _ := ScoreRecon(profile, event.Path, event.Timestamp, cfg)
	if penalty < 0.25 {
		t.Errorf("Expected high 404 penalty, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected reasons for high 404 rate")
	}
}

func TestSensitivePathDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	cfg := GetConfig()

	event := &RequestEvent{
		IP:        "192.168.1.1",
		Path:      "/.env",
		Timestamp: 1000,
	}

	penalty, reasons, _ := ScoreRecon(profile, event.Path, event.Timestamp, cfg)
	if penalty < 0.5 {
		t.Errorf("Expected sensitive path penalty, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected reasons for sensitive path hit")
	}
}

func TestBruteForceDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.EndpointTimestamps["/login"] = []float64{1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009,
		1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021}

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Path:      "/login",
		Method:    "POST",
		Timestamp: 1030,
	}

	penalty, reasons := ScoreBruteForce(profile, event, cfg)
	if penalty < 0.5 {
		t.Errorf("Expected brute force penalty, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected brute force reasons")
	}
}

func TestDDoSBurstDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	for i := 0; i < 25; i++ {
		profile.BurstTimestamps = append(profile.BurstTimestamps, float64(i))
	}

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Timestamp: 1000,
	}

	penalty, reasons := ScoreDDoS(profile, event, cfg)
	if penalty < 0.8 {
		t.Errorf("Expected DDoS burst penalty, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected DDoS burst reasons")
	}
}

func TestSessionAnomalyDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.HadHomepage = false
	profile.HadLoginFlow = false
	profile.TotalRequests = 2

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Path:      "/admin",
		Timestamp: 1000,
	}

	penalty, reasons, _ := ScoreSession(profile, event, cfg)
	if penalty < 0.4 {
		t.Errorf("Expected session anomaly penalty, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected session anomaly reasons")
	}
}

func TestScrapingDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.NonAssetRequestCount = 15
	profile.AssetRequestCount = 0

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Timestamp: 1000,
	}

	penalty, reasons, _ := ScoreScraping(profile, event, cfg)
	if penalty < 0.3 {
		t.Errorf("Expected scraping penalty for no assets, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected scraping reasons")
	}
}

func TestEvasionDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.SeenUserAgents["UA1"] = true
	profile.SeenUserAgents["UA2"] = true
	profile.SeenUserAgents["UA3"] = true
	profile.SeenUserAgents["UA4"] = true
	profile.SeenUserAgents["UA5"] = true

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Timestamp: 1000,
	}

	penalty, reasons := ScoreEvasion(profile, event, cfg)
	if penalty < 0.5 {
		t.Errorf("Expected evasion penalty for UA rotation, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected evasion reasons")
	}
}

func TestVulnerabilityProbing(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")

	cfg := GetConfig()
	// Test repeated 500s detection
	profile.Repeated500Endpoints["/api/crash"] = 6
	
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Path:      "/api/crash",
		StatusCode: 500,  // Must be 500 to trigger
		Timestamp: 1000,
	}

	penalty, reasons, _ := ScoreVulnProbe(profile, event, cfg)
	if penalty < 0.6 {
		t.Errorf("Expected vuln probe penalty >= 0.6 for repeated 500s, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected vuln probe reasons")
	}
}

func TestAccountAbuseDetection(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.LoginAttempts = 120

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Timestamp: 1000,
	}

	penalty, reasons := ScoreAccountAbuse(profile, event, cfg)
	if penalty < 0.3 {
		t.Errorf("Expected account abuse penalty, got %f", penalty)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected account abuse reasons")
	}
}

func TestTrustBoost(t *testing.T) {
	profile := NewIPProfile("192.168.1.1")
	profile.FirstSeen = 100
	profile.SeenUserAgents["Mozilla/5.0"] = true
	profile.SeenJA4["fingerprint123"] = true
	profile.AssetRequestCount = 30
	profile.NonAssetRequestCount = 10
	profile.HasValidReferer = true
	profile.IsDatacenter = false
	profile.IsTor = false
	profile.IsVPN = false
	profile.SeenCountryCodes["US"] = true
	profile.HadHomepage = true
	profile.HadLoginFlow = true
	profile.RecentTimestamps = []float64{100, 101, 102, 105, 110}

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "192.168.1.1",
		Timestamp: 500,
	}

	boost, reasons, _ := ComputeTrustBoost(profile, event, cfg)
	if boost < 0.5 {
		t.Errorf("Expected trust boost, got %f", boost)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected trust boost reasons")
	}
}

func TestFullTrustScoreCalculation(t *testing.T) {
	testEvent := map[string]interface{}{
		"ip":                "192.168.1.1",
		"session_id":        "session123",
		"timestamp":         1700000000.0,
		"method":            "GET",
		"path":              "/",
		"query_string":      "",
		"status_code":       200.0,
		"response_size":     5000.0,
		"request_size":      100.0,
		"content_type":      "text/html",
		"user_agent":        "Mozilla/5.0",
		"referer":           "https://example.com",
		"accept":            "text/html",
		"accept_language":   "en-US",
		"ja4_fingerprint":   "t13d1516h2_8daaf6152771_b0da82dd1658",
		"asn":               "AS15169",
		"country_code":      "US",
		"is_tor":            false,
		"is_vpn":            false,
		"is_datacenter":     false,
		"is_asset_request":  false,
	}

	result := ProcessEvent(testEvent)

	// Verify result has all required fields
	if result["score"] == nil {
		t.Error("Result missing score field")
	}
	if result["decision"] == nil {
		t.Error("Result missing decision field")
	}
	if result["sub_scores"] == nil {
		t.Error("Result missing sub_scores field")
	}

	score := result["score"].(float64)
	if score < 0 || score > 10 {
		t.Errorf("Score out of range [0-10]: %f", score)
	}

	decision := result["decision"].(string)
	validDecisions := map[string]bool{
		"allow":          true,
		"allow+stricter": true,
		"challenge":      true,
		"block":          true,
		"ban":           true,
	}
	if !validDecisions[decision] {
		t.Errorf("Invalid decision: %s", decision)
	}
}

func TestSuspiciousActivityDetection(t *testing.T) {
	// Test 1: Scanning behavior (high 404 rate)
	event1 := map[string]interface{}{
		"ip":                "10.0.0.1",
		"session_id":        "scan123",
		"timestamp":         1700000000.0,
		"method":            "GET",
		"path":              "/admin",
		"query_string":      "",
		"status_code":       404.0,
		"response_size":     0.0,
		"request_size":      0.0,
		"content_type":      "",
		"user_agent":        "scanner/1.0",
		"referer":           "",
		"accept":            "*/*",
		"accept_language":   "",
		"ja4_fingerprint":   "scan_fp",
		"asn":               "AS4134",
		"country_code":      "CN",
		"is_tor":            false,
		"is_vpn":            false,
		"is_datacenter":     false,
		"is_asset_request":  false,
	}

	profile := NewIPProfile("10.0.0.1")
	for i := 0; i < 100; i++ {
		profile.TotalRequests++
		profile.Total404++
	}

	cfg := GetConfig()
	event := &RequestEvent{
		IP:        "10.0.0.1",
		Path:      event1["path"].(string),
		Timestamp: event1["timestamp"].(float64),
	}

	penalty, _, _ := ScoreRecon(profile, event.Path, event.Timestamp, cfg)
	if penalty < 0.25 {
		t.Errorf("Should detect high 404 rate (scanning), got penalty %f", penalty)
	}

	// Test 2: Possible brute force - check if rate is high enough to trigger
	profile2 := NewIPProfile("10.0.0.2")
	timestamps := make([]float64, 0)
	for i := 0; i < 25; i++ {
		timestamps = append(timestamps, 1700000000.0+float64(i*2))
	}
	profile2.EndpointTimestamps["/login"] = timestamps

	event2 := &RequestEvent{
		IP:        "10.0.0.2",
		Path:      "/login",
		Method:    "POST",
		Timestamp: 1700000100.0,
	}

	penalty2, _ := ScoreBruteForce(profile2, event2, cfg)
	if penalty2 < 0.3 {
		t.Errorf("Should detect elevated login rate, got penalty %f", penalty2)
	}
}

func TestJSONOutput(t *testing.T) {
	testEvent := map[string]interface{}{
		"ip":                "185.220.101.45",
		"session_id":        "abc123",
		"timestamp":         1700000000.0,
		"method":            "GET",
		"path":              "/.env",
		"query_string":      "",
		"status_code":       404.0,
		"response_size":     0.0,
		"request_size":      0.0,
		"content_type":      "",
		"user_agent":        "python-requests/2.28.0",
		"referer":           "",
		"accept":            "*/*",
		"accept_language":   "",
		"ja4_fingerprint":   "t13d1516h2_8daaf6152771_b0da82dd1658",
		"asn":               "AS4134",
		"country_code":      "CN",
		"is_tor":            false,
		"is_vpn":            true,
		"is_datacenter":     true,
		"is_asset_request":  false,
	}

	result := ProcessEvent(testEvent)
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Errorf("Failed to marshal result to JSON: %v", err)
	}

	if len(jsonBytes) == 0 {
		t.Error("JSON output is empty")
	}

	fmt.Println("Sample JSON output:")
	fmt.Println(string(jsonBytes))
}
