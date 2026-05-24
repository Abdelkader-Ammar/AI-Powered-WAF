package trustscore

import "sync"

type IdentityContext struct {
	UserID           string
	AccountCreatedAt float64 // 0 = unknown/unauthenticated
	EmailVerified    bool
	MFAEnabled       bool
	ResolvedBy       string // "jwt" | "headers" | "auth_api" | "anonymous"
}

type GatekeeperVerdict struct {
	IPScore     float64
	UserScore   float64 // -1 if no user profile exists yet
	EverBlocked bool
	Recommended string // "allow" / "allow+stricter" / "challenge" / "block" / "ban"
}

type RequestEvent struct {
	IP              string    `json:"ip"`
	SessionID       string    `json:"session_id"`
	Timestamp       float64   `json:"timestamp"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	QueryString     string    `json:"query_string"`
	StatusCode      int       `json:"status_code"`
	ResponseSize    int       `json:"response_size"`
	RequestSize     int       `json:"request_size"`
	ContentType     string    `json:"content_type"`
	UserAgent       string    `json:"user_agent"`
	Referer         string    `json:"referer"`
	Accept          string    `json:"accept"`
	AcceptLanguage  string    `json:"accept_language"`
	JA4Fingerprint  string    `json:"ja4_fingerprint"`
	ASN             string    `json:"asn"`
	ChallengePassed bool      `json:"challenge_passed"`
	CountryCode     string    `json:"country_code"`
	IsTor           bool      `json:"is_tor"`
	IsVPN           bool      `json:"is_vpn"`
	IsDatacenter    bool      `json:"is_datacenter"`
	IsAssetRequest  bool      `json:"is_asset_request"`
}

type IPProfile struct {
	mu                      sync.RWMutex
	IP                      string
	FirstSeen               float64
	LastSeen                float64
	TotalRequests           int
	Total404                int
	Total403                int
	Total500                int
	Total200                int
	UniqueEndpoints         map[string]bool
	EndpointMethods         map[string]map[string]bool
	SensitivePathHits       []SensitiveHit
	NumericIDSequences      map[string][]int
	RecentTimestamps        []float64
	BurstTimestamps         []float64
	EndpointTimestamps      map[string][]float64
	LoginAttempts           int
	PasswordResetAttempts   int
	RegistrationAttempts    int
	SessionID               string
	SessionStart            float64
	PagesVisited            []string
	HadHomepage             bool
	HadLoginFlow            bool
	CountryCode             string
	ASN                     string
	IsTor                   bool
	IsVPN                   bool
	IsDatacenter            bool
	SeenCountryCodes        map[string]bool
	SeenUserAgents          map[string]bool
	SeenJA4                 map[string]bool
	FirstUserAgent          string
	FirstJA4                string
	AssetRequestCount       int
	NonAssetRequestCount    int
	HasValidReferer         bool
	PaginationSequences     map[string][]int
	RateLimitPauses         int
	Last429Ts               float64
	ParamFuzzingSequences   map[string][]string
	Repeated500Endpoints    map[string]int
	PreviousScores          []float64
	WasBlocked              bool
	WasChallenged           bool
	ChallengeSolvedRecently bool
	ChallengeSolvedAt       float64
	EWMAScore               float64            // Tier 1 correction score [0-1]
	Tier1Corrections        []Tier1Correction
	RASPHits                []RASPHit          // Tier 2 (RASP) ground-truth effects
	ConfirmedExploit        bool               // sticky: set on a CRITICAL RASP hit
}

type SensitiveHit struct {
	Path      string
	Timestamp float64
}

type SubScores struct {
	Recon       float64
	BruteForce  float64
	DDoS        float64
	Session     float64
	Scraping    float64
	Evasion     float64
	VulnProbe   float64
	AccountAbuse float64
}

type ReasonItem struct {
	Module   string  `json:"module"`
	Reason   string  `json:"reason"`
	SubScore float64 `json:"sub_score"`
}

type TrustScoreResult struct {
	IP              string          `json:"ip"`
	Score           float64         `json:"score"`
	Decision        string          `json:"decision"`
	SubScores       SubScores       `json:"sub_scores"`
	Boost           float64         `json:"boost"`
	Reasons         []ReasonItem    `json:"reasons"`
	BoostReasons    []string        `json:"boost_reasons"`
	ProfileAgeSec   float64         `json:"profile_age_s"`
	Timestamp       float64         `json:"timestamp"`
}

func NewIPProfile(ip string) *IPProfile {
	return &IPProfile{
		IP:                   ip,
		FirstSeen:            0,
		LastSeen:             0,
		TotalRequests:        0,
		Total404:             0,
		Total403:             0,
		Total500:             0,
		Total200:             0,
		UniqueEndpoints:      make(map[string]bool),
		EndpointMethods:      make(map[string]map[string]bool),
		SensitivePathHits:    []SensitiveHit{},
		NumericIDSequences:   make(map[string][]int),
		RecentTimestamps:     []float64{},
		BurstTimestamps:      []float64{},
		EndpointTimestamps:   make(map[string][]float64),
		LoginAttempts:        0,
		PasswordResetAttempts: 0,
		RegistrationAttempts: 0,
		SessionID:            "",
		SessionStart:         0,
		PagesVisited:         []string{},
		HadHomepage:          false,
		HadLoginFlow:         false,
		CountryCode:          "",
		ASN:                  "",
		IsTor:                false,
		IsVPN:                false,
		IsDatacenter:         false,
		SeenCountryCodes:     make(map[string]bool),
		SeenUserAgents:       make(map[string]bool),
		SeenJA4:              make(map[string]bool),
		FirstUserAgent:       "",
		FirstJA4:             "",
		AssetRequestCount:    0,
		NonAssetRequestCount: 0,
		HasValidReferer:      false,
		PaginationSequences:  make(map[string][]int),
		RateLimitPauses:      0,
		Last429Ts:            0,
		ParamFuzzingSequences: make(map[string][]string),
		Repeated500Endpoints: make(map[string]int),
		PreviousScores:       []float64{},
		WasBlocked:              false,
		WasChallenged:           false,
		ChallengeSolvedRecently: false,
		ChallengeSolvedAt:       0,
		EWMAScore:               0.5, // neutral starting point
		Tier1Corrections:        []Tier1Correction{},
	}
}

func (p *IPProfile) Update(event *RequestEvent, signals DetectionSignals, outcome RequestOutcome) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := event.Timestamp

	// Expire challenge-solved boost after 10 minutes
	if p.ChallengeSolvedRecently && now-p.ChallengeSolvedAt > 600 {
		p.ChallengeSolvedRecently = false
	}

	if p.FirstSeen == 0 {
		p.FirstSeen = now
		p.FirstUserAgent = event.UserAgent
		p.FirstJA4 = event.JA4Fingerprint
		p.SessionStart = now
		p.SessionID = event.SessionID
	}

	p.LastSeen = now
	p.TotalRequests++

	switch event.StatusCode {
	case 404:
		p.Total404++
	case 403:
		p.Total403++
	case 500:
		p.Total500++
	case 200:
		p.Total200++
	}

	// Apply Recon signals
	if signals.Recon.SensitivePathHit {
		p.SensitivePathHits = append(p.SensitivePathHits, signals.Recon.SensitiveHit)
	}
	if signals.Recon.NewNumericID != 0 {
		p.NumericIDSequences[signals.Recon.IDSequenceBasePath] = append(
			p.NumericIDSequences[signals.Recon.IDSequenceBasePath],
			signals.Recon.NewNumericID,
		)
		p.NumericIDSequences[signals.Recon.IDSequenceBasePath] = removeDuplicatesAndSort(
			p.NumericIDSequences[signals.Recon.IDSequenceBasePath],
		)
	}

	// Apply Session signals
	p.HadHomepage = p.HadHomepage || signals.Session.HadHomepage
	p.HadLoginFlow = p.HadLoginFlow || signals.Session.HadLoginFlow

	// Apply Scraping signals
	if signals.Scraping.PaginationPath != "" {
		if p.PaginationSequences == nil {
			p.PaginationSequences = make(map[string][]int)
		}
		p.PaginationSequences[signals.Scraping.PaginationPath] = append(
			p.PaginationSequences[signals.Scraping.PaginationPath],
			signals.Scraping.PageNumber,
		)
	}

	// Apply VulnProbe signals
	if signals.VulnProbe.ParamFuzzing {
		if p.ParamFuzzingSequences == nil {
			p.ParamFuzzingSequences = make(map[string][]string)
		}
		p.ParamFuzzingSequences[signals.VulnProbe.ParamFuzzingBase] = append(
			p.ParamFuzzingSequences[signals.VulnProbe.ParamFuzzingBase],
			signals.VulnProbe.ParamFuzzingVal,
		)
	}
	if signals.VulnProbe.Repeated500 {
		if p.Repeated500Endpoints == nil {
			p.Repeated500Endpoints = make(map[string]int)
		}
		p.Repeated500Endpoints[signals.VulnProbe.Repeated500Path]++
	}

	// Apply Boost signals — reset counters when challenge passed
	if signals.Boost.PassedChallenge {
		p.Total403 = 0
		p.Total404 = 0
		p.Total500 = 0
		p.LoginAttempts = 0
		p.PasswordResetAttempts = 0
		p.RegistrationAttempts = 0
	}

	p.UniqueEndpoints[event.Path] = true

	if p.EndpointMethods[event.Path] == nil {
		p.EndpointMethods[event.Path] = make(map[string]bool)
	}
	p.EndpointMethods[event.Path][event.Method] = true

	p.RecentTimestamps = append(p.RecentTimestamps, now)
	p.RecentTimestamps = trimTimestamps(p.RecentTimestamps, now, 60)

	p.BurstTimestamps = append(p.BurstTimestamps, now)
	p.BurstTimestamps = trimTimestamps(p.BurstTimestamps, now, 1.0)

	if p.EndpointTimestamps[event.Path] == nil {
		p.EndpointTimestamps[event.Path] = []float64{}
	}
	p.EndpointTimestamps[event.Path] = append(p.EndpointTimestamps[event.Path], now)
	p.EndpointTimestamps[event.Path] = trimTimestamps(p.EndpointTimestamps[event.Path], now, 60)

	p.SeenUserAgents[event.UserAgent] = true
	p.SeenJA4[event.JA4Fingerprint] = true

	p.CountryCode = event.CountryCode
	p.SeenCountryCodes[event.CountryCode] = true
	p.IsTor = event.IsTor
	p.IsVPN = event.IsVPN
	p.IsDatacenter = event.IsDatacenter

	if event.IsAssetRequest {
		p.AssetRequestCount++
	} else {
		p.NonAssetRequestCount++
		p.PagesVisited = append(p.PagesVisited, event.Path)
	}

	if event.Referer != "" && isValidReferer(event.Referer) {
		p.HasValidReferer = true
	}

	if event.StatusCode == 429 {
		p.Last429Ts = now
	} else if p.Last429Ts > 0 && now-p.Last429Ts > 5 {
		p.RateLimitPauses++
		p.Last429Ts = 0
	}

	// Apply outcome
	p.PreviousScores = append(p.PreviousScores, outcome.FinalScore)
	if len(p.PreviousScores) > 10 {
		p.PreviousScores = p.PreviousScores[1:]
	}
	if outcome.WasBlocked {
		p.WasBlocked = true
	}
	if outcome.WasChallenged {
		p.WasChallenged = true
	}
}

func trimTimestamps(timestamps []float64, now float64, window float64) []float64 {
	var result []float64
	for _, t := range timestamps {
		if now-t <= window {
			result = append(result, t)
		}
	}
	return result
}

func isValidReferer(referer string) bool {
	suspicious := []string{"sqlmap", "nikto", "burp", "scanner"}
	refererLower := referer
	for _, s := range suspicious {
		if contains(refererLower, s) {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}


