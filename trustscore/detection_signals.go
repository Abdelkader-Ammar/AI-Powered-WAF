package trustscore

// DetectionSignals carries all observations from scoring functions that
// must be applied to IPProfile by Update(). This separation lets scoring
// functions run under RLock (concurrent-safe) while mutations happen later
// under Lock.
type DetectionSignals struct {
	Recon    ReconSignals
	Session  SessionSignals
	Scraping ScrapingSignals
	VulnProbe VulnProbeSignals
	Boost    BoostSignals
	RASP     RASPSignals
}

type ReconSignals struct {
	SensitivePathHit    bool // true if current path hit a sensitive path
	SensitiveHit        SensitiveHit
	IDSequenceLength    int
	NewNumericID        int
	IDSequenceBasePath  string // path prefix for NumericIDSequences key
}

type SessionSignals struct {
	HadHomepage  bool
	HadLoginFlow bool
}

type ScrapingSignals struct {
	PaginationPath string // non-empty if a pagination was detected
	PageNumber     int
}

type VulnProbeSignals struct {
	ParamFuzzing     bool
	ParamFuzzingBase string // key for ParamFuzzingSequences
	ParamFuzzingVal  string // value to append
	Repeated500      bool
	Repeated500Path  string
}

type BoostSignals struct {
	PassedChallenge bool
}

// RequestOutcome is written back to IPProfile after scoring is complete.
type RequestOutcome struct {
	FinalScore   float64
	Decision     string
	WasBlocked   bool
	WasChallenged bool
}
