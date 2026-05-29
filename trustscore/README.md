# Dynamic Trust Engine (UEBA)

This module is the **User and Entity Behavior Analytics (UEBA)** engine for the AI-Powered WAF. Written entirely in Golang, it provides sub-millisecond risk scoring for both unauthenticated IPs and authenticated users.

## How the TrustScore Works

The Trust Engine assigns every IP and User a score ranging from **0.0 (Malicious)** to **10.0 (Highly Trusted)**. New visitors start at **7.5**.

### The 5 Decision Thresholds
When you call the engine, it returns a struct containing the calculated `Score` and an explicit `Decision` string. The Orchestrator MUST enforce these decisions on subsequent requests:

| Score Range | Decision String | What the Orchestrator Should Do |
| :--- | :--- | :--- |
| **8.0 – 10.0** | `allow` | **trusted account.** we only call the lightgbm model to determine if we allow or block the request, and call coraza only if the lightgbm result is uncertain. lgbm then coraza only if the lgbm result is uncertain. highest req/sec rate-limit |
| **5.0 – 7.9** | `allow+stricter`| **Permit, but stricter.** both lgbm and coraza must return `allow` for the request to be forwarded, lower threshholds to forward to tier 1 for deep request inspection. both lgbm and coraza fired simultaneously to save time, lower req/sec rate-limit than allow|
| **3.0 – 4.9** | `challenge` | **Intercept.** Serve a JS challenge or CAPTCHA. if captcha is not solved, the request is blocked. if treated like allow+stricter, lower rate-limit than allow+stricter and allow |
| **1.0 – 2.9** | `block` | **Reject.** Return HTTP 403 Forbidden. temporarily ban the entity that made the request (user or ip, depends if authenticated request or not ) |
| **0.0 – 0.9** | `ban` | **banned.** the entity is permanently banned. |

### The 8 Behavioral Modules (Layer 1: IP)
For every HTTP request, the engine calculates a weighted penalty across 8 detection modules:
1. **Reconnaissance (20%)**: High 404/403 rates, hitting sensitive paths (e.g., `/.env`), sequential ID enumeration.
2. **Brute Force (18%)**: High-rate POSTs to `/login` or `/register`, mechanical bot timings.
3. **DDoS (15%)**: Request bursts (>20 req/s), sustained volumetric floods, expensive endpoint hammering.
4. **Session Anomalies (12%)**: Impossible travel (multiple countries), bypassing warmup (hitting `/admin` without `/login`).
5. **Scraping (10%)**: Pagination tracking (`?page=30`), missing asset requests (headless browsers).
6. **Evasion (10%)**: Rotating User-Agents, rotating JA4 TLS fingerprints, Tor/VPN/Datacenter detection.
7. **Vuln Probing (10%)**: Parameter fuzzing (`?id=1` -> `?id=1'`), intentionally triggering repeated 500 errors.
8. **Account Abuse (5%)**: Mass account creations in short timeframes.

### Trust Boosters (Good Behavior)
To reduce false positives, legitimate behavior *reduces* risk (increasing the score):
- Human-like, irregular timing (Coefficient of Variation > 0.8).
- Loading standard CSS/JS assets (browser behavior).
- Returning visitors with clean histories.
- Successfully verified Email or MFA (Layer 2).

### Hard Policy Overrides
Certain behaviors bypass the weighted average and force a graded decision. Each
override value sits inside its target band (recall: `challenge` is 3.0–4.9,
`block` is 1.0–2.9, `ban` is below 1.0):
- **Confirmed RASP exploit** → Score 0.0 (`ban`)
- **RASP HIGH-severity effect** → Score 2.0 (`block`)
- **Sensitive-path probing** → 1–2 hits: 4.0 (`challenge`); 3–7 hits: 2.0 (`block`); 8+ hits: 0.0 (`ban`)
- **Failed logins** → 8+: 2.0 (`block`); 40+: 0.0 (`ban`)
- **Request bursts** → over 15 req/s: 4.0 (`challenge`); over 50 req/s: 0.0 (`ban`)
- **Tor exit node + any attack signal** → Score 4.0 (`challenge`)
- **Multiple countries in one session** → Score 2.0 (`block`)

---

## Deployment Architecture

This module is **NOT a standalone microservice**. It is a **Golang Package**.
The Orchestrator imports this module and compiles it directly into its own binary. This guarantees zero network overhead and sub-millisecond memory access when checking traffic.

## Orchestrator Integration Guide

Because the Trust Engine needs to see the **response** of the server (or the block decision from Tier 0/1) to accurately catch reconnaissance (404s) and vulnerability probing (500s), the integration happens in two steps during the HTTP lifecycle:

### Step 1: Pre-Request Check (The Gatekeeper)
When a request first hits the Orchestrator, BEFORE passing it to Tier 0 or the backend, you can optionally check the current reputation of the IP/User. This uses a single unified function. Pass `""` for `userID` if the request is unauthenticated.

```go
import "trustscore"

// Fetch profiles (if guest, pass "" for userID. If logged in, pass "user_abc")
ipProfile, userProfile := trustscore.GetGatekeeperProfiles(clientIP, userID, event.Timestamp)

// 1. Always check the physical IP's history
if ipProfile.WasBlocked || (len(ipProfile.PreviousScores) > 0 && ipProfile.PreviousScores[0] < 3.0) {
    // Return 403 immediately without bothering Tier 0 / Tier 1
}

// 2. If they are logged in, check their User Account history
if userProfile != nil {
    if userProfile.Score < 3.0 || userProfile.EverBlocked {
        // Return 403 or force an MFA/CAPTCHA challenge
    }
}
```

### Step 2: Post-Response Update (The Learner)
**After** the backend has responded (or **after** Tier 0/1 has blocked the request), the Orchestrator asynchronously calls the Trust Engine to update the reputation. 

*If Tier 0/1 blocks the request, ensure the `StatusCode` is set to `403` or `406` so the Trust Engine knows the request was malicious.*

```go
// 1. Build the Event asynchronously after the response is sent
event := &trustscore.RequestEvent{
    IP:             "185.220.101.45",
    SessionID:      "sess_123",
    Timestamp:      float64(time.Now().Unix()),
    Method:         "POST",
    Path:           "/login",
    QueryString:    "",
    StatusCode:     403,   
    ResponseSize:   512,
    RequestSize:    128,
    ContentType:    "application/json",
    UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    Referer:        "https://example.com/login",
    Accept:         "application/json",
    AcceptLanguage: "en-US,en;q=0.9",
    JA4Fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
    // ASN:            "AS15169", auto-resolved via InitGeoLookup
    // CountryCode:    "US-California", auto-resolved via InitGeoLookup
    // IsTor, IsVPN, IsDatacenter are auto-resolved via InitProxyDetection
    // IsAssetRequest is auto-detected from Path file extension
}

// 2. Unauthenticated Traffic (IP-layer only)
profile := trustscore.GetOrCreateProfile(event.IP)
result := trustscore.ComputeTrustScore(profile, event)

// 3. Authenticated Traffic (IP + User layer EWMA)
userID := "user_abc123"

// For logins, sync the 3 required fields from your Auth DB:
if event.Path == "/login" {
    userProfile := trustscore.DefaultUserStore.Load(userID, event.Timestamp)
    userProfile.AccountCreatedAt = authDB.GetCreationTime(userID)
    userProfile.EmailVerified = authDB.IsEmailVerified(userID)
    userProfile.MFAEnabled = authDB.HasMFA(userID)
}

userResult := trustscore.ComputeUserTrustScore(userID, event, trustscore.DefaultUserStore)

// 4. Redis is updated automatically!
```

## Redis State Management

The Trust Engine automatically pushes a minimal, blazing-fast 2-column database (`ID -> TrustScore`) to Redis. 

The Orchestrator simply needs to initialize the connection once at startup:
```go
func main() {
	// 1. Proxy Init Path
	trustscore.InitProxyDetection("./geo2ip/IP2PROXY-LITE-PX1/IP2PROXY-LITE-PX1.BIN")
	defer trustscore.CloseIPIntelligence()

	// 2. Location & ASN Init Paths
	geoPath := "./geo2ip/IP2LOCATION-LITE-DB11/IP2LOCATION-LITE-DB11.BIN"
	asnPath := "./geo2ip/IP2LOCATION-LITE-ASN/IP2LOCATION-LITE-ASN.BIN"

	err := trustscore.InitLocationIntelligence(geoPath, asnPath)
	if err != nil {
		log.Fatalf("Failed to initialize location intelligence: %v", err)
	}
	defer trustscore.CloseLocationIntelligence()

	// 3. Initialize optional fast-lookup Redis store
	trustscore.InitRedis("localhost:6379", "password", 0)
	defer trustscore.CloseRedis()

	// Start Orchestrator HTTP listener...
}
```
Every time `ProcessEvent` or `ProcessEventForUser` finishes calculating a new score, it instantly calls `Set(ctx, ID, Score)` in Redis. The Orchestrator can use this Redis store to universally block bad IPs across distributed clusters.

## Testing

The engine includes 28 unit tests covering all mathematical time windows, module triggers, and EWMA scoring. Run them via:
```bash
go test ./...
```

## Known Limitations

1. **IP Profile Store Constraints**: The `IPStore` is currently implemented as a hardcoded `map[string]*IPProfile` without an interface (unlike `UserStore`). This prevents swapping it for a Redis-backed store, meaning multiple WAF instances currently share no IP state. For multi-node deployments, **sticky routing** at the load balancer is the recommended mitigation until an interface is introduced in a future refactor.
2. **Redis Exporter Ephemerality**: The Redis exporter currently only persists the `id → score` mapping (the fast read path), not the full behavioral profile history. This means that a process restart wipes all behavioral history, and every IP and user will start fresh. This is a known technical debt that will be addressed in a future dedicated effort.
