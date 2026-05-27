package trustscore

// GetOrCreateProfile returns the IPProfile for ip via the package-level
// DefaultIPStore (see ip_store.go), creating one if absent. The store owns
// persistence and eviction, so this layer can be swapped for a Redis- or
// SQL-backed implementation without touching the scoring code.
func GetOrCreateProfile(ip string) *IPProfile {
	return DefaultIPStore.Load(ip)
}

// GetGatekeeperProfiles fetches the current state for a request to make early routing decisions.
// If userID is empty (""), it only returns the IP profile, and userProfile will be nil.
func GetGatekeeperProfiles(ip string, userID string, timestamp float64) (*IPProfile, *UserTrustProfile) {
	ipProfile := GetOrCreateProfile(ip)

	var userProfile *UserTrustProfile
	if userID != "" {
		userProfile = DefaultUserStore.Load(userID, timestamp)
	}

	return ipProfile, userProfile
}

// Gatekeeper is a pre-request check that reads the current profile scores
// and makes a recommendation without mutating the stored state.
func Gatekeeper(ip string, userID string, timestamp float64) *GatekeeperVerdict {
	ipProfile, userProfile := GetGatekeeperProfiles(ip, userID, timestamp)

	ipScore := 7.5
	if len(ipProfile.PreviousScores) > 0 {
		ipScore = ipProfile.PreviousScores[len(ipProfile.PreviousScores)-1]
	} else if ipProfile.LastSeen > 0 {
		ipScore = 7.5 // default if no score history but seen
	}

	verdict := &GatekeeperVerdict{
		IPScore:     ipScore,
		UserScore:   -1.0,
		EverBlocked: ipProfile.WasBlocked,
	}

	scoreToUse := ipScore
	if userProfile != nil {
		verdict.UserScore = userProfile.Score
		if userProfile.EverBlocked {
			verdict.EverBlocked = true
		}
		scoreToUse = userProfile.Score
	}

	verdict.Recommended = makeDecision(scoreToUse)

	// Hard blocks that bypass standard threshold logic
	if verdict.EverBlocked {
		// Just challenge previously blocked entities instead of permanently blocking again here
		// unless scoreToUse is low enough to block naturally
		if verdict.Recommended == "allow" || verdict.Recommended == "allow+stricter" {
			verdict.Recommended = "challenge"
		}
	}

	return verdict
}

func ProcessEvent(rawEvent map[string]interface{}) map[string]interface{} {
	event := ParseRawEvent(rawEvent)
	profile := GetOrCreateProfile(event.IP)
	result := ComputeTrustScore(profile, event)

	// Export ONLY the IP and Score to Redis (Minimal 2-column database)
	ExportScore(event.IP, result.Score)

	return map[string]interface{}{
		"ip":            event.IP,
		"score":         result.Score,
		"decision":      result.Decision,
		"sub_scores":    result.SubScores,
		"boost":         result.Boost,
		"reasons":       result.Reasons,
		"boost_reasons": result.BoostReasons,
		"profile_age_s": result.ProfileAgeSec,
		"timestamp":     event.Timestamp,
	}
}

// ProcessEventForUser is the authenticated-user entry point.
// Call this for every request where you know the user's ID (i.e. after login).
// It runs both the IP-layer score and the user-layer score, returning the
// combined result keyed on the user ID.
//
// userID  — your application's stable user identifier (e.g. UUID from JWT)
// rawEvent — same map shape as ProcessEvent
func ProcessEventForUser(ctx *IdentityContext, rawEvent map[string]interface{}) map[string]interface{} {
	event := ParseRawEvent(rawEvent)
	result := ComputeUserTrustScore(ctx, event, DefaultUserStore)

	// Export ONLY the User ID and Score to Redis (Minimal 2-column database)
	ExportScore(ctx.UserID, result.Score)

	signals := make([]map[string]interface{}, len(result.Signals))
	for i, s := range result.Signals {
		signals[i] = map[string]interface{}{
			"module":    s.Module,
			"reason":    s.Reason,
			"sub_score": s.SubScore,
		}
	}

	return map[string]interface{}{
		"user_id":         result.UserID,
		"score":           result.Score,
		"score_delta":     result.ScoreDelta,
		"previous_score":  result.PreviousScore,
		"decision":        result.Decision,
		"ip_score":        result.IPScore,
		"signals":         signals,
		"boost_signals":   result.BoostSignals,
		"raw_event_score": result.RawEventScore,
		"account_age_s":   result.AccountAgeSec,
		"timestamp":       result.Timestamp,
	}
}

// RecordChallengeSolved marks that an IP (and optionally a user) has
// successfully solved a challenge. This provides a trust boost for the next
// 10 minutes via ChallengeSolvedRecently.
func RecordChallengeSolved(ip, userID string, now float64) {
	profile := GetOrCreateProfile(ip)
	profile.mu.Lock()
	profile.ChallengeSolvedRecently = true
	profile.ChallengeSolvedAt = now
	profile.mu.Unlock()

	if userID != "" {
		userProfile := DefaultUserStore.Load(userID, now)
		userProfile.mu.Lock()
		userProfile.ChallengeSolvedRecently = true
		userProfile.ChallengeSolvedAt = now
		userProfile.mu.Unlock()
	}
}

// ParseRawEvent converts a raw map into a typed RequestEvent.
// Extracted so both ProcessEvent and ProcessEventForUser share the same logic.
func ParseRawEvent(rawEvent map[string]interface{}) *RequestEvent {
	// Safely parse string fields
	safeString := func(key string) string {
		if val, ok := rawEvent[key].(string); ok {
			return val
		}
		return ""
	}

	ip := safeString("ip")
	requestPath := safeString("path")

	// 1. Resolve Proxy Signals (IP2Proxy)
	isTor, isVPN, isDatacenter := false, false, false

	// Default to map values, but if missing (or we want to override), we do it properly:
	mapIsTor, okTor := rawEvent["is_tor"].(bool)
	mapIsVPN, okVPN := rawEvent["is_vpn"].(bool)
	mapIsDC, okDC := rawEvent["is_datacenter"].(bool)

	geoTor, geoVPN, geoDC := EnrichIPData(ip)

	if okTor {
		isTor = mapIsTor
	} else {
		isTor = geoTor
	}
	if okVPN {
		isVPN = mapIsVPN
	} else {
		isVPN = geoVPN
	}
	if okDC {
		isDatacenter = mapIsDC
	} else {
		isDatacenter = geoDC
	}

	// 2. Resolve Geo Location and ASN Signals (IP2Location DB11)
	asn, combinedLocation := "", ""

	// Safely check if ASN and CountryCode exist in the map
	mapASN, okASN := rawEvent["asn"].(string)
	mapCC, okCC := rawEvent["country_code"].(string)

	// If either is missing, fetch from the local database
	var geoCC, geoRegion, geoASN string
	if !okASN || !okCC {
		geoCC, geoRegion, geoASN = GetASNAndRegion(ip)
	}

	// Assign ASN: Map takes priority, fallback to local DB
	if okASN && mapASN != "" {
		asn = mapASN
	} else {
		asn = geoASN
	}

	// Assign Location: Map takes priority, fallback to combining CC and Region from local DB
	if okCC && mapCC != "" {
		combinedLocation = mapCC
	} else {
		// Combine into format like "US-California"
		if geoCC != "" && geoRegion != "" && geoRegion != "-" {
			combinedLocation = geoCC + "-" + geoRegion
		} else if geoCC != "" {
			combinedLocation = geoCC // Fallback if region is unknown
		}
	}

	// 3. Resolve Asset Requests
	isAssetRequest := false
	if v, ok := rawEvent["is_asset_request"].(bool); ok {
		isAssetRequest = v
	} else {
		isAssetRequest = IsAssetPath(requestPath)
	}

	// 4. Resolve Challenge Passed
	challengePassed := false
	if v, ok := rawEvent["challenge_passed"].(bool); ok {
		challengePassed = v
	}

	// Safely parse float64 fields
	safeFloatToInt := func(key string) int {
		if val, ok := rawEvent[key].(float64); ok {
			return int(val)
		}
		return 0
	}


	// Safely parse float64 fields
	safeFloat := func(key string) float64 {
		if val, ok := rawEvent[key].(float64); ok {
			return val
		}
		return 0.0
	}

	return &RequestEvent{
		IP:             ip,
		SessionID:      safeString("session_id"),
		Timestamp:      safeFloat("timestamp"),
		Method:         safeString("method"),
		Path:           requestPath,
		QueryString:    safeString("query_string"),
		StatusCode:     safeFloatToInt("status_code"),
		ResponseSize:   safeFloatToInt("response_size"),
		RequestSize:    safeFloatToInt("request_size"),
		ContentType:    safeString("content_type"),
		UserAgent:      safeString("user_agent"),
		Referer:        safeString("referer"),
		Accept:         safeString("accept"),
		AcceptLanguage: safeString("accept_language"),
		JA4Fingerprint: safeString("ja4_fingerprint"),
		ASN:            asn,
		CountryCode:    combinedLocation, // Now contains "CC-Region"
		IsTor:          isTor,
		IsVPN:          isVPN,
		IsDatacenter:   isDatacenter,
		IsAssetRequest: isAssetRequest,
		ChallengePassed: challengePassed,
	}
}
