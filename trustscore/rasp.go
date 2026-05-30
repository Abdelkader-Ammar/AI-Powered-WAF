package trustscore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// ── RASP (Tier 2) integration ───────────────────────────────────────────────
//
// The RASP agent (a separate C process embedded in / beneath the backend)
// observes the backend's real system calls and database queries and emits a
// ground-truth verdict per dangerous effect. This file is the Go-side ingest:
// it receives those verdicts, attaches them to the IP / user trust profiles, and
// exposes ScoreRASP so the fusion layer can act on them. Because RASP verdicts
// are evidence (not probabilities), HIGH/CRITICAL effects drive the score via the
// hard-override path (see checkHardOverrides), while MEDIUM/LOW influence the
// weighted fusion through the additive "rasp" module.

// Severity ladder. Stored as an int on RASPHit so a zeroed hit is "none".
const (
	sevNone = iota
	sevLow
	sevMedium
	sevHigh
	sevCritical
)

const maxRASPHits = 100

// RASPEvent is one verdict decoded from the agent's JSON stream. Field names
// match the C agent's rasp_event_t.
type RASPEvent struct {
	RequestID string  `json:"request_id"`
	IP        string  `json:"ip"`
	UserID    string  `json:"user_id"`
	Timestamp float64 `json:"timestamp"`
	Category  string  `json:"category"` // rce|lfi|webshell|ssrf|sqli|db_unauth|anomaly
	Severity  string  `json:"severity"` // critical|high|medium|low
	Action    string  `json:"action"`   // blocked|killed|observed
	Evidence  string  `json:"evidence"` // argv[0], path, or table.column
}

// RASPHit is a confirmed runtime effect persisted on a profile.
type RASPHit struct {
	Category  string
	Severity  int
	Evidence  string
	Timestamp float64
}

// RASPSignals carries the sticky exploit flag through the DetectionSignals seam.
type RASPSignals struct {
	ConfirmedExploit bool
}

func parseSeverity(s string) int {
	switch s {
	case "critical":
		return sevCritical
	case "high":
		return sevHigh
	case "medium":
		return sevMedium
	case "low":
		return sevLow
	default:
		return sevNone
	}
}

// AddRASPHit attaches a confirmed effect to an IP profile. A CRITICAL effect is
// ground truth, so it sets the sticky ConfirmedExploit flag and pushes a 0.0
// onto PreviousScores + WasBlocked, so the in-memory Gatekeeper (which reads
// PreviousScores) bans the very next request from this IP.
func (p *IPProfile) AddRASPHit(hit RASPHit) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.RASPHits) >= maxRASPHits {
		p.RASPHits = p.RASPHits[1:]
	}
	p.RASPHits = append(p.RASPHits, hit)
	if hit.Severity == sevCritical {
		p.ConfirmedExploit = true
		p.WasBlocked = true
		p.PreviousScores = append(p.PreviousScores, 0.0)
	}
}

// AddRASPHit attaches a confirmed effect to a user profile. On a CRITICAL effect
// it drives the long-term Score straight to 0 and sets the sticky flags, so the
// Gatekeeper (which reads userProfile.Score) bans the account on its next
// request rather than waiting for the EWMA to wash down.
func (u *UserTrustProfile) AddRASPHit(hit RASPHit) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.RASPHits) >= maxRASPHits {
		u.RASPHits = u.RASPHits[1:]
	}
	u.RASPHits = append(u.RASPHits, hit)
	if hit.Severity == sevCritical {
		u.ConfirmedExploit = true
		u.EverBlocked = true
		u.Score = 0.0
		u.ScoreHistory = append(u.ScoreHistory, 0.0)
		if len(u.ScoreHistory) > 30 {
			u.ScoreHistory = u.ScoreHistory[1:]
		}
	}
}

// ScoreRASP turns confirmed runtime effects into a sub-score in [0,1]. These are
// ground truth, so the severity→penalty map is steep and CRITICAL saturates. The
// caller (ComputeTrustScore Phase 1) already holds the profile RLock.
func ScoreRASP(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string, RASPSignals) {
	penalty := 0.0
	var reasons []string
	var signals RASPSignals

	for _, hit := range profile.RASPHits {
		switch hit.Severity {
		case sevCritical:
			penalty = 1.0
			signals.ConfirmedExploit = true
			reasons = append(reasons, fmt.Sprintf("rasp_critical:%s:%s", hit.Category, hit.Evidence))
		case sevHigh:
			if penalty < 0.85 {
				penalty = 0.85
			}
			reasons = append(reasons, "rasp_high:"+hit.Category)
		case sevMedium:
			if penalty < 0.45 {
				penalty = 0.45
			}
			reasons = append(reasons, "rasp_medium:"+hit.Category)
		case sevLow:
			if penalty < 0.20 {
				penalty = 0.20
			}
			reasons = append(reasons, "rasp_low:"+hit.Category)
		}
	}
	return penalty, reasons, signals
}

// raspMaxSeverity reports the highest RASP severity recorded on a profile.
// Caller must hold at least the profile RLock.
func raspMaxSeverity(profile *IPProfile) int {
	maxSev := sevNone
	for _, hit := range profile.RASPHits {
		if hit.Severity > maxSev {
			maxSev = hit.Severity
		}
	}
	return maxSev
}

// ProcessRASPEvent applies one ground-truth effect to the trust state. It is the
// RASP analogue of ProcessEvent: it mutates the profile(s) and exports the
// cratered score to Redis so the next request is gatekept at the edge.
func ProcessRASPEvent(ev RASPEvent) {
	sev := parseSeverity(ev.Severity)
	if sev == sevNone || ev.IP == "" {
		return
	}
	hit := RASPHit{
		Category:  ev.Category,
		Severity:  sev,
		Evidence:  ev.Evidence,
		Timestamp: ev.Timestamp,
	}

	ipProfile := GetOrCreateProfile(ev.IP)
	ipProfile.AddRASPHit(hit)
	switch sev {
	case sevCritical:
		ExportScore(ev.IP, 0.0) // makeDecision(0.0) → Gatekeeper bans next request
	case sevHigh:
		ExportScore(ev.IP, 2.0) // makeDecision(2.0) → block
	}

	if ev.UserID != "" {
		up := DefaultUserStore.Load(ev.UserID, ev.Timestamp)
		up.AddRASPHit(hit)
		switch sev {
		case sevCritical:
			ExportScore(ev.UserID, 0.0)
		case sevHigh:
			ExportScore(ev.UserID, 2.0)
		}
		DefaultUserStore.Save(up)
	}

	log.Printf("[RASP] %s severity=%s category=%s ip=%s user=%s action=%s evidence=%q",
		ev.RequestID, ev.Severity, ev.Category, ev.IP, ev.UserID, ev.Action, ev.Evidence)

	pushRASPEventToRedis(ev)
}

// pushRASPEventToRedis publishes a capped "Confirmed Exploitation" feed the
// dashboard renders, so operators see the category, severity, action, and
// evidence of every ground-truth effect. No-op if Redis isn't initialised.
func pushRASPEventToRedis(ev RASPEvent) {
	if redisClient == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	redisClient.LPush(ctx, "waf:rasp:events", b)
	redisClient.LTrim(ctx, "waf:rasp:events", 0, 99)
}

// StartRASPIngest listens on a unix socket for newline-delimited JSON RASPEvents
// from the C agent and applies each one. Called once at startup (from
// tier-0/main.go), analogous to InitRedis. Returns an error if the socket cannot
// be bound; the caller may log-and-continue so the WAF runs without the RASP.
func StartRASPIngest(socketPath string) error {
	if socketPath == "" {
		return fmt.Errorf("rasp ingest: empty socket path")
	}
	// Remove a stale socket from a previous run before binding.
	if _, err := os.Stat(socketPath); err == nil {
		_ = os.Remove(socketPath)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("rasp ingest listen %s: %w", socketPath, err)
	}
	log.Printf("[RASP] ingest listening on unix:%s", socketPath)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("[RASP] accept error: %v", err)
				return
			}
			go handleRASPConn(conn)
		}
	}()
	return nil
}

// handleRASPConn decodes a stream of JSON RASPEvent objects from one agent
// connection. The agent may batch many events on a single long-lived connection.
func handleRASPConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev RASPEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Printf("[RASP] bad event: %v", err)
			continue
		}
		ProcessRASPEvent(ev)
	}
}
