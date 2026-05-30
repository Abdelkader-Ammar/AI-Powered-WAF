package trustscore

import "testing"

// A confirmed CRITICAL RASP effect must collapse the IP score to 0 → "ban",
// bypassing the weighted fusion.
func TestRASPCriticalBansIP(t *testing.T) {
	profile := NewIPProfile("10.0.0.9")
	profile.AddRASPHit(RASPHit{
		Category: "rce", Severity: sevCritical,
		Evidence: "execve /bin/sh", Timestamp: 1000,
	})
	event := &RequestEvent{IP: "10.0.0.9", Path: "/", Timestamp: 1001}

	res := ComputeTrustScore(profile, event)
	if res.Score != 0.0 {
		t.Errorf("expected score 0.0 after CRITICAL RASP, got %v", res.Score)
	}
	if res.Decision != "ban" {
		t.Errorf("expected decision ban, got %q", res.Decision)
	}
	if !profile.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit flag to be set")
	}
}

// A HIGH RASP effect forces a "block" (score 2.0, in the 1.0–2.9 block range).
func TestRASPHighBlocksIP(t *testing.T) {
	profile := NewIPProfile("10.0.0.10")
	profile.AddRASPHit(RASPHit{
		Category: "ssrf", Severity: sevHigh,
		Evidence: "connect 169.254.169.254", Timestamp: 1000,
	})
	event := &RequestEvent{IP: "10.0.0.10", Path: "/", Timestamp: 1001}

	res := ComputeTrustScore(profile, event)
	if res.Decision != "block" {
		t.Errorf("expected decision block, got %q (score %v)", res.Decision, res.Score)
	}
}

// A clean profile (no RASP hits) scores exactly as before the RASP module was
// added — the rasp term is 0 and must not perturb the calibrated baseline.
func TestRASPNoHitsIsNeutral(t *testing.T) {
	profile := NewIPProfile("10.0.0.11")
	event := &RequestEvent{IP: "10.0.0.11", Path: "/", Timestamp: 1001}

	res := ComputeTrustScore(profile, event)
	// New, clean IP with no penalties → full trust (10) → allow.
	if res.Score < 9.0 {
		t.Errorf("expected near-full trust for a clean IP, got %v", res.Score)
	}
	if res.Decision != "allow" {
		t.Errorf("expected allow for a clean IP, got %q", res.Decision)
	}
}

// ProcessRASPEvent must drive the score through the in-memory store so the
// next Gatekeeper read bans the entity.
func TestProcessRASPEventBansViaGatekeeper(t *testing.T) {
	ip := "10.0.0.12"
	ProcessRASPEvent(RASPEvent{
		IP: ip, Severity: "critical", Category: "rce",
		Evidence: "execve /bin/sh", Timestamp: 2000,
	})
	verdict := Gatekeeper(ip, "", 2001)
	if verdict.Recommended != "ban" {
		t.Errorf("expected Gatekeeper to ban after CRITICAL RASP, got %q",
			verdict.Recommended)
	}
}

// A negative Tier 1 correction (EWMAScore below the 0.5 neutral point) must
// lower the computed score; a positive one must raise it.
func TestTier1CorrectionMovesScore(t *testing.T) {
	event := &RequestEvent{IP: "10.0.0.13", Path: "/", Timestamp: 1001}

	base := NewIPProfile("10.0.0.13")
	baseRes := ComputeTrustScore(base, event)

	risky := NewIPProfile("10.0.0.14")
	risky.EWMAScore = 0.0 // Tier 1 says "malicious" with full confidence
	event2 := &RequestEvent{IP: "10.0.0.14", Path: "/", Timestamp: 1001}
	riskyRes := ComputeTrustScore(risky, event2)

	if !(riskyRes.Score < baseRes.Score) {
		t.Errorf("expected Tier 1 negative correction to lower score: base=%v risky=%v",
			baseRes.Score, riskyRes.Score)
	}
}
