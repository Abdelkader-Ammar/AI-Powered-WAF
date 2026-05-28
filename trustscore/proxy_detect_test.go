package trustscore

import (
	"os"
	"testing"
)

func TestProxyDetection(t *testing.T) {
	// Override with IP2PROXY_DB; defaults to the local geo2ip data directory.
	dbPath := os.Getenv("IP2PROXY_DB")
	if dbPath == "" {
		dbPath = "../geo2ip/IP2PROXY-LITE-PX1/IP2PROXY-LITE-PX1.BIN"
	}
	// 1. Check if the database exists locally before running the test
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skipf("Skipping proxy test: database not found at %s", dbPath)
	}

	// 2. Test Initialization
	err := InitProxyDetection(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize proxy database: %v", err)
	}
	defer CloseProxyDetection()

	// 3. Define Test Cases
	tests := []struct {
		name      string
		ip        string
		expectTor bool
		expectVPN bool
		expectDC  bool
	}{
		{
			name:      "Clean Normal IP (Google DNS)",
			ip:        "8.8.8.8",
			expectTor: false,
			expectVPN: false,
			// Depending on the proxy DB version, 8.8.8.8 might be flagged as a Datacenter (DCH) or PUB.
			// You can adjust expectDC to true if your specific IP2Proxy tier flags DNS servers.
			expectDC: false,
		},
		{
			name:      "Invalid IP Address",
			ip:        "999.999.999.999",
			expectTor: false,
			expectVPN: false,
			expectDC:  false,
		},
		// Note: To test a real VPN/Tor node, you would need to look up a current, active
		// Tor exit node IP and add it here. Because they rotate, hardcoding one in a test
		// can lead to flaky tests if the DB updates and drops that IP.
	}

	// 4. Run Tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isTor, isVPN, isDC := EnrichIPData(tt.ip)

			if isTor != tt.expectTor {
				t.Errorf("Expected IsTor %v, got %v", tt.expectTor, isTor)
			}
			if isVPN != tt.expectVPN {
				t.Errorf("Expected IsVPN %v, got %v", tt.expectVPN, isVPN)
			}
			if isDC != tt.expectDC {
				t.Errorf("Expected IsDC %v, got %v", tt.expectDC, isDC)
			}
		})
	}
}
