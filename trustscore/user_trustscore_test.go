package trustscore

import (
	"math"
	"testing"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func makeTestEvent(ip, sessionID, method, path, country, ja4 string,
	timestamp, statusCode float64, isVPN, isTor bool) *RequestEvent {
	return &RequestEvent{
		IP:             ip,
		SessionID:      sessionID,
		Timestamp:      timestamp,
		Method:         method,
		Path:           path,
		QueryString:    "",
		StatusCode:     int(statusCode),
		ResponseSize:   512,
		RequestSize:    128,
		ContentType:    "application/json",
		UserAgent:      "Mozilla/5.0",
		Referer:        "",
		Accept:         "*/*",
		AcceptLanguage: "en-US",
		JA4Fingerprint: ja4,
		ASN:            "AS36925",
		CountryCode:    country,
		IsTor:          isTor,
		IsVPN:          isVPN,
		IsDatacenter:   false,
		IsAssetRequest: false,
	}
}

func freshStore() UserStore {
	return NewMemoryUserStore()
}

// ─── Test 1: EWMA update moves score toward new observation ───────────────────

func TestEWMAUpdate(t *testing.T) {
	p := NewUserProfile("usr_1", 1000.0)
	p.Score = 8.0
	p.Alpha = 0.15

	// Observe a bad event (raw score 2.0) — score should drop but not collapse.
	p.UpdateEWMA(2.0)

	expected := 0.15*2.0 + 0.85*8.0
	if math.Abs(p.Score-expected) > 0.01 {
		t.Errorf("EWMA update: expected %.4f, got %.4f", expected, p.Score)
	}
	if p.Score >= 8.0 {
		t.Errorf("Score should have dropped after bad event, got %.2f", p.Score)
	}
	if len(p.ScoreHistory) != 1 {
		t.Errorf("Expected 1 entry in ScoreHistory, got %d", len(p.ScoreHistory))
	}
}

func TestEWMARecovery(t *testing.T) {
	p := NewUserProfile("usr_2", 1000.0)
	p.Score = 3.0 // damaged score
	p.Alpha = 0.15

	// Many clean events should slowly pull the score up.
	for i := 0; i < 20; i++ {
		p.UpdateEWMA(9.5)
	}
	if p.Score <= 3.0 {
		t.Errorf("Score should have recovered from 3.0, got %.2f", p.Score)
	}
	if p.Score >= 9.5 {
		t.Errorf("Score should not reach 9.5 immediately (EWMA inertia), got %.2f", p.Score)
	}
}

// ─── Test 2: KnownIP / KnownCountry / KnownJA4 helpers ───────────────────────

func TestKnownIPHelpers(t *testing.T) {
	p := NewUserProfile("usr_3", 1000.0)
	p.KnownIPs = []string{"1.2.3.4", "5.6.7.8"}

	if !p.IsKnownIP("1.2.3.4") {
		t.Error("Expected 1.2.3.4 to be known")
	}
	if p.IsKnownIP("9.9.9.9") {
		t.Error("Expected 9.9.9.9 to be unknown")
	}

	p.KnownCountries = []string{"TN", "FR"}
	if !p.IsKnownCountry("TN") {
		t.Error("Expected TN to be known")
	}
	if p.IsKnownCountry("RU") {
		t.Error("Expected RU to be unknown")
	}

	p.KnownJA4s = []string{"ja4_aaa"}
	if !p.IsKnownJA4("ja4_aaa") {
		t.Error("Expected ja4_aaa to be known")
	}
	if p.IsKnownJA4("ja4_zzz") {
		t.Error("Expected ja4_zzz to be unknown")
	}
}

// ─── Test 3: RecordLogin updates counters and known lists ─────────────────────

func TestRecordLogin(t *testing.T) {
	p := NewUserProfile("usr_4", 1000.0)
	ev := makeTestEvent("10.0.0.1", "s1", "POST", "/login", "TN", "ja4_x", 1000.0, 200, false, false)

	p.RecordLogin(ev, true)

	if p.TotalSuccessLogins != 1 {
		t.Errorf("Expected 1 success login, got %d", p.TotalSuccessLogins)
	}
	if !p.IsKnownIP("10.0.0.1") {
		t.Error("IP should be added to KnownIPs on successful login")
	}
	if !p.IsKnownCountry("TN") {
		t.Error("Country should be added on successful login")
	}

	// Failed login should not add to known lists but should increment counter
	ev2 := makeTestEvent("10.0.0.2", "s2", "POST", "/login", "RU", "ja4_y", 1001.0, 401, false, false)
	p.RecordLogin(ev2, false)
	if p.TotalFailedLogins != 1 {
		t.Errorf("Expected 1 failed login, got %d", p.TotalFailedLogins)
	}
	if p.IsKnownIP("10.0.0.2") {
		t.Error("IP should NOT be added on failed login")
	}
}

// ─── Test 4: UserStore load/save/delete ───────────────────────────────────────

func TestMemoryUserStore(t *testing.T) {
	store := freshStore()

	// Load creates a fresh profile
	p := store.Load("usr_5", 1000.0)
	if p == nil {
		t.Fatal("Expected non-nil profile")
	}
	if p.UserID != "usr_5" {
		t.Errorf("Expected userID usr_5, got %s", p.UserID)
	}
	if p.Score != 7.5 {
		t.Errorf("Expected initial score 7.5, got %.2f", p.Score)
	}

	// Modify and save
	p.Score = 9.0
	store.Save(p)

	// Load again — should return the saved version
	p2 := store.Load("usr_5", 2000.0)
	if p2.Score != 9.0 {
		t.Errorf("Expected saved score 9.0, got %.2f", p2.Score)
	}

	// Delete
	store.Delete("usr_5")
	p3 := store.Load("usr_5", 3000.0)
	if p3.Score != 7.5 {
		t.Errorf("After delete, expected fresh score 7.5, got %.2f", p3.Score)
	}
}

// ─── Test 5: ScoreUserBehavior — failed logins trigger penalty ────────────────

func TestFailedLoginPenalty(t *testing.T) {
	p := NewUserProfile("usr_6", 1000.0)
	p.TotalFailedLogins = 5 // already has 5 failed logins

	ev := makeTestEvent("10.0.0.1", "s1", "POST", "/login", "TN", "ja4_a", 1000.0, 401, false, false)
	signals := UserBehaviorSignals{
		IsLoginEvent: true,
		LoginFailed:  true,
		IPScore:      8.0,
	}

	penalty, _, reasons, _ := ScoreUserBehavior(p, ev, signals)

	if penalty <= 0 {
		t.Error("Expected non-zero penalty for repeated failed logins")
	}
	if len(reasons) == 0 {
		t.Error("Expected at least one penalty reason")
	}
}

// ─── Test 6: ScoreUserBehavior — new country triggers penalty ─────────────────

func TestNewCountryLoginPenalty(t *testing.T) {
	p := NewUserProfile("usr_7", 1000.0)
	p.KnownCountries = []string{"TN"}
	p.TotalSuccessLogins = 5

	ev := makeTestEvent("91.108.4.1", "s1", "POST", "/login", "RU", "ja4_a", 1000.0, 200, false, false)
	signals := UserBehaviorSignals{
		IsLoginEvent: true,
		LoginSucceeded: true,
		IsNewCountry: true, // RU not in KnownCountries
		IPScore:      7.0,
	}

	penalty, _, reasons, _ := ScoreUserBehavior(p, ev, signals)

	if penalty <= 0 {
		t.Errorf("Expected penalty for new-country login, got %.3f", penalty)
	}
	found := false
	for _, r := range reasons {
		if r.Module == "user_geo" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected user_geo reason for new country login")
	}
}

// ─── Test 7: ScoreUserBehavior — MFA enabled gives boost ─────────────────────

func TestMFABoost(t *testing.T) {
	p := NewUserProfile("usr_8", 1000.0)
	ev := makeTestEvent("10.0.0.1", "s1", "GET", "/dashboard", "TN", "ja4_a", 1000.0, 200, false, false)
	signals := UserBehaviorSignals{
		MFAEnabled: true,
		IPScore:    9.0,
	}

	_, boost, _, boostReasons := ScoreUserBehavior(p, ev, signals)

	if boost <= 0 {
		t.Error("Expected positive boost when MFA is enabled")
	}
	found := false
	for _, r := range boostReasons {
		if r == "mfa_enabled" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'mfa_enabled' in boost reasons")
	}
}

// ─── Test 8: ComputeUserTrustScore — trusted user gets allow decision ─────────

func TestTrustedUserAllowed(t *testing.T) {
	store := freshStore()
	userID := "usr_trusted_9"

	// Pre-populate with trusted history
	p := store.Load(userID, 1000.0)
	p.KnownIPs = []string{"10.0.0.1"}
	p.KnownCountries = []string{"TN"}
	p.KnownJA4s = []string{"ja4_good"}
	p.TotalSuccessLogins = 20
	p.AccountCreatedAt = 1000.0 - 90*86400 // 90 days old
	p.MFAEnabled = true
	p.EmailVerified = true
	p.Score = 9.0
	p.ScoreHistory = []float64{9.0, 9.1, 9.0, 8.9, 9.0, 9.1, 9.0}
	store.Save(p)

	ev := makeTestEvent("10.0.0.1", "sess_t1", "GET", "/dashboard", "TN", "ja4_good",
		1000.0+86400, 200, false, false)

	result := ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev, store)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.Score < 7.0 {
		t.Errorf("Trusted user should have score >= 7.0, got %.2f", result.Score)
	}
	if result.Decision == "block" || result.Decision == "ban" {
		t.Errorf("Trusted user should not be blocked, got decision: %s", result.Decision)
	}
}

// ─── Test 9: ComputeUserTrustScore — attacker gets degraded score ─────────────

func TestAttackerScoreDegrades(t *testing.T) {
	store := freshStore()
	userID := "usr_attacker_10"

	// Pre-seed the user as having known country TN, so RU login is flagged as new.
	p := store.Load(userID, 999.0)
	p.KnownCountries = []string{"TN"}
	p.TotalSuccessLogins = 3
	store.Save(p)

	ev1 := makeTestEvent("91.108.4.55", "bad_sess", "POST", "/login", "RU", "ja4_bad",
		1000.0, 401, true, false)
	ev2 := makeTestEvent("91.108.4.55", "bad_sess", "POST", "/login", "RU", "ja4_bad",
		1005.0, 401, true, false)
	ev3 := makeTestEvent("91.108.4.55", "bad_sess", "POST", "/login", "RU", "ja4_bad",
		1010.0, 401, true, false)

	r1 := ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev1, store)
	_ = ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev2, store)
	r3 := ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev3, store)

	// Repeated failed logins from VPN + new country should produce a suspicious score.
	// Score should not be near-maximum.
	if r3.Score >= 9.0 {
		t.Errorf("Score should not be near-max with repeated failures from VPN+new country: r1=%.2f, r3=%.2f", r1.Score, r3.Score)
	}
	// New country login policy override should escalate beyond plain "allow"
	if r3.Decision == "allow" {
		t.Errorf("Expected non-allow decision after 3 failed logins from VPN+new country, got: %s", r3.Decision)
	}
}

// ─── Test 10: Hard override — 20+ failed logins forces block score ────────────

func TestHardOverrideFailedLogins(t *testing.T) {
	store := freshStore()
	userID := "usr_heavy_fail_11"

	p := store.Load(userID, 1000.0)
	p.TotalFailedLogins = 20 // pre-seed
	store.Save(p)

	ev := makeTestEvent("1.2.3.4", "s1", "POST", "/login", "CN", "ja4_x",
		1000.0, 401, false, false)

	result := ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev, store)

	if result.Score > 3.0 {
		t.Errorf("Expected hard-override score <= 3.0 for 20+ failed logins, got %.2f", result.Score)
	}
	if result.Decision == "allow" || result.Decision == "allow+stricter" {
		t.Errorf("Expected block/challenge for 20+ failed logins, got: %s", result.Decision)
	}
}

// ─── Test 11: Policy override — new-country login escalates to allow+stricter ──

func TestNewCountryPolicyOverride(t *testing.T) {
	store := freshStore()
	userID := "usr_newcountry_12"

	p := store.Load(userID, 1000.0)
	p.KnownCountries = []string{"TN"}
	p.TotalSuccessLogins = 5
	p.Score = 9.0
	p.KnownIPs = []string{"10.0.0.1"}
	p.KnownJA4s = []string{"ja4_ok"}
	p.AccountCreatedAt = 1000.0 - 60*86400
	store.Save(p)

	// Login from a new country — score may still be high but decision should be escalated
	ev := makeTestEvent("91.108.4.1", "s_new", "POST", "/login", "RU", "ja4_ok",
		1000.0+100, 200, false, false)

	result := ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev, store)

	if result.Decision == "allow" {
		t.Errorf("New-country login should be escalated beyond 'allow', got: %s", result.Decision)
	}
}

// ─── Test 12: Score delta is computed correctly ───────────────────────────────

func TestScoreDeltaComputed(t *testing.T) {
	store := freshStore()
	userID := "usr_delta_13"

	p := store.Load(userID, 1000.0)
	p.Score = 8.0
	store.Save(p)

	ev := makeTestEvent("10.0.0.1", "s1", "GET", "/dashboard", "TN", "ja4_ok",
		1000.0, 200, false, false)

	result := ComputeUserTrustScore(&IdentityContext{UserID: userID}, ev, store)

	expectedDelta := math.Round((result.Score-8.0)*100) / 100
	if math.Abs(result.ScoreDelta-expectedDelta) > 0.02 {
		t.Errorf("ScoreDelta mismatch: got %.2f, expected %.2f", result.ScoreDelta, expectedDelta)
	}
	if result.PreviousScore != 8.0 {
		t.Errorf("PreviousScore should be 8.0, got %.2f", result.PreviousScore)
	}
}

// ─── Test 13: AverageRecentScore helper ──────────────────────────────────────

func TestAverageRecentScore(t *testing.T) {
	p := NewUserProfile("usr_14", 1000.0)
	p.ScoreHistory = []float64{9.0, 8.0, 7.0, 6.0, 5.0}

	avg5 := p.AverageRecentScore(5)
	expected := (9.0 + 8.0 + 7.0 + 6.0 + 5.0) / 5.0
	if math.Abs(avg5-expected) > 0.01 {
		t.Errorf("AverageRecentScore(5): expected %.2f, got %.2f", expected, avg5)
	}

	// Requesting more than available should use all available
	avg10 := p.AverageRecentScore(10)
	if math.Abs(avg10-expected) > 0.01 {
		t.Errorf("AverageRecentScore(10) with 5 entries: expected %.2f, got %.2f", expected, avg10)
	}
}

// ─── Test 14: ProcessEventForUser returns valid JSON-serialisable output ──────

func TestProcessEventForUserOutput(t *testing.T) {
	// Reset the default store for isolation
	DefaultUserStore = NewMemoryUserStore()

	rawEvent := map[string]interface{}{
		"ip": "10.20.30.40", "session_id": "sess_json_test",
		"timestamp": 1700500000.0, "method": "GET", "path": "/dashboard",
		"query_string": "", "status_code": 200.0, "response_size": 2048.0,
		"request_size": 0.0, "content_type": "text/html",
		"user_agent": "Mozilla/5.0", "referer": "", "accept": "text/html",
		"accept_language": "en-US", "ja4_fingerprint": "ja4_test_fp",
		"asn": "AS36925", "country_code": "TN",
		"is_tor": false, "is_vpn": false, "is_datacenter": false, "is_asset_request": false,
	}

	result := ProcessEventForUser(&IdentityContext{UserID: "usr_json_test_15"}, rawEvent)

	requiredKeys := []string{
		"user_id", "score", "score_delta", "previous_score",
		"decision", "ip_score", "signals", "boost_signals",
		"raw_event_score", "timestamp",
	}
	for _, k := range requiredKeys {
		if _, ok := result[k]; !ok {
			t.Errorf("Missing required key in output: %s", k)
		}
	}

	score, ok := result["score"].(float64)
	if !ok {
		t.Error("score should be float64")
	}
	if score < 0 || score > 10 {
		t.Errorf("score out of range [0,10]: %.2f", score)
	}

	decision, ok := result["decision"].(string)
	if !ok {
		t.Error("decision should be string")
	}
	validDecisions := map[string]bool{
		"allow": true, "allow+stricter": true, "challenge": true,
		"block": true, "ban": true,
	}
	if !validDecisions[decision] {
		t.Errorf("Invalid decision value: %s", decision)
	}
}
