package trustscore

import (
	"os"
	"testing"
)

func TestLocationDetection(t *testing.T) {
	// The IP2Location LITE .BIN databases are large, separately-licensed files
	// that are NOT committed to the repo (see .gitignore: geo2ip/, *.bin). They
	// must be provided to run this test. Resolve their paths from env vars, with
	// a repo-relative default, and SKIP (not fail) when they are absent — a
	// missing data fixture is not a code failure.
	geoPath := os.Getenv("IP2LOCATION_DB")
	if geoPath == "" {
		geoPath = "../geo2ip/IP2LOCATION-LITE-DB11/IP2LOCATION-LITE-DB11.BIN"
	}
	asnPath := os.Getenv("IP2LOCATION_ASN")
	if asnPath == "" {
		asnPath = "../geo2ip/IP2LOCATION-LITE-ASN/IP2LOCATION-LITE-ASN.BIN"
	}
	if _, err := os.Stat(geoPath); err != nil {
		t.Skipf("geo database not present (%s); set IP2LOCATION_DB / "+
			"IP2LOCATION_ASN to run this test", geoPath)
	}

	err := InitLocationIntelligence(geoPath, asnPath)
	if err != nil {
		t.Fatalf("Failed to initialize location databases: %v", err)
	}
	defer CloseLocationIntelligence()

	// 3. Define Test Cases
	tests := []struct {
		name          string
		ip            string
		wantCountry   string
		wantASN       string
		expectMatches bool // true if we expect a valid lookup, false if invalid
	}{
		{
			name:          "Valid Google IP",
			ip:            "8.8.8.8",
			wantCountry:   "US",
			wantASN:       "15169", // Google's ASN
			expectMatches: true,
		},
		{
			name:          "Invalid IP String",
			ip:            "not-an-ip",
			wantCountry:   "",
			wantASN:       "",
			expectMatches: false,
		},
	}

	// 4. Run Tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country, region, asn := GetASNAndRegion(tt.ip)

			if tt.expectMatches {
				if country != tt.wantCountry {
					t.Errorf("Expected country %q, got %q", tt.wantCountry, country)
				}
				if asn != tt.wantASN {
					t.Errorf("Expected ASN %q, got %q", tt.wantASN, asn)
				}
				if region == "" {
					t.Errorf("Expected a region, got empty string")
				}
			} else {
				if country != "" || asn != "" || region != "" {
					t.Errorf("Expected empty results for invalid IP, got %q, %q, %q", country, region, asn)
				}
			}
		})
	}
}
