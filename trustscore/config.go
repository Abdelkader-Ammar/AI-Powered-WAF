package trustscore

import "sync"

type Config struct {
	// Recon
	ReconHighRate404       float64
	ReconMediumRate404     float64
	ReconHighRate403       float64
	EndpointDiversityThreshold float64
	IDEnumMinSequence      int
	MethodProbeMin         int

	// Brute force
	BruteLoginHigh        int
	BruteLoginMedium      int
	BruteResetHigh        int
	BruteRegisterHigh     int
	BruteCVBotThreshold   float64
	BruteCumulativeLogin  int

	// DDoS
	DDOSBurstHigh          int
	DDOSBurstMedium        int
	DDOSRateHigh           float64
	DDOSRateMedium         float64
	DDOSExpensiveRate      int
	DDOSLargePayloadBytes  int

	// Scraping
	ScrapePaginationHigh   int
	ScrapePaginationMedium int
	ScrapeCVThreshold      float64

	// Evasion
	EvasionUARotationHigh  int
	EvasionUARotationMedium int
	EvasionJA4Rotation     int
	EvasionPeriodicCV      float64
	EvasionPauseResumeCount int

	// Vuln probe
	VulnFuzzMinSeq         int
	Vuln500High            int
	Vuln500Medium          int
	VulnOptionsFlood       int

	// Account abuse
	AbuseRegisterHigh      int
	AbuseRegisterMedium    int
	AbuseResetHigh         int
	AbuseCumulativeHigh    int

	// Trust boosters
	BoostHumanCVMin        float64
	BoostAssetRatioMin     float64

	// Tier 1 (RoBERTa) feedback. Tier1ScoreGain bounds how many score points a
	// fully-confident Tier 1 correction (EWMAScore at 0 or 1) can move the score.
	Tier1ScoreGain         float64
}

var DefaultConfig = Config{
	// Recon
	ReconHighRate404:       0.50,
	ReconMediumRate404:     0.25,
	ReconHighRate403:       0.40,
	EndpointDiversityThreshold: 20.0,
	IDEnumMinSequence:      5,
	MethodProbeMin:         4,

	// Brute force
	BruteLoginHigh:        20,
	BruteLoginMedium:      10,
	BruteResetHigh:        5,
	BruteRegisterHigh:     10,
	BruteCVBotThreshold:   0.20,
	BruteCumulativeLogin:  50,

	// DDoS
	DDOSBurstHigh:         20,
	DDOSBurstMedium:       10,
	DDOSRateHigh:          20.0,
	DDOSRateMedium:        8.0,
	DDOSExpensiveRate:     5,
	DDOSLargePayloadBytes: 1_000_000,

	// Scraping
	ScrapePaginationHigh:   30,
	ScrapePaginationMedium: 10,
	ScrapeCVThreshold:      0.25,

	// Evasion
	EvasionUARotationHigh:  5,
	EvasionUARotationMedium: 3,
	EvasionJA4Rotation:     3,
	EvasionPeriodicCV:      0.05,
	EvasionPauseResumeCount: 2,

	// Vuln probe
	VulnFuzzMinSeq:        6,
	Vuln500High:           5,
	Vuln500Medium:         3,
	VulnOptionsFlood:      10,

	// Account abuse
	AbuseRegisterHigh:     5,
	AbuseRegisterMedium:   3,
	AbuseResetHigh:        3,
	AbuseCumulativeHigh:   100,

	// Trust boosters
	BoostHumanCVMin:       0.80,
	BoostAssetRatioMin:    0.30,

	// Tier 1 feedback
	Tier1ScoreGain:        3.0,
}

var configMu sync.RWMutex

func GetConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return DefaultConfig
}

func SetConfig(c Config) {
	configMu.Lock()
	defer configMu.Unlock()
	DefaultConfig = c
}
