package trustscore

import (
	"fmt"
	"math"
)

var ProtectedEndpoints = map[string]bool{
	"/dashboard":      true,
	"/admin":          true,
	"/profile":        true,
	"/settings":       true,
	"/api/user":       true,
	"/checkout":       true,
	"/api/orders":     true,
	"/account":        true,
}

var WarmupPages = map[string]bool{
	"/":       true,
	"/home":   true,
	"/index":  true,
	"/login":  true,
	"/signup": true,
}

func ScoreSession(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string, SessionSignals) {
	penalty := 0.0
	var reasons []string
	var signals SessionSignals

	if ProtectedEndpoints[event.Path] && !profile.HadHomepage && !profile.HadLoginFlow && 	profile.TotalRequests < 3 {
		penalty += 0.5
		reasons = append(reasons, fmt.Sprintf("no_warmup:direct_access_to:%s", event.Path))
	}

	if WarmupPages[event.Path] {
		signals.HadHomepage = true
	}
	if (event.Path == "/login" || event.Path == "/auth/login" || event.Path == "/signin") && event.StatusCode == 200 {
		signals.HadLoginFlow = true
	}

	if len(profile.SeenCountryCodes) > 1 && profile.SessionID == event.SessionID {
		penalty += 0.7
		var countries []string
		for c := range profile.SeenCountryCodes {
			countries = append(countries, c)
		}
		reasons = append(reasons, fmt.Sprintf("impossible_travel:countries=%v", countries))
	}

	pages := profile.PagesVisited
	if event.Path == "/checkout/confirm" {
		found := false
		for _, p := range pages {
			if p == "/cart" {
				found = true
				break
			}
		}
		if !found {
			penalty += 0.4
			reasons = append(reasons, "order_violation:checkout_without_cart")
		}
	}

	if len(event.Path) > len("/api/orders/") && event.Path[:len("/api/orders/")] == "/api/orders/" && event.Method == "POST" {
		pageStr := ""
		for _, p := range pages {
			pageStr += " " + p
		}
		if !contains(pageStr, "/checkout") {
			penalty += 0.35
			reasons = append(reasons, "order_violation:order_without_checkout_flow")
		}
	}

	if ProtectedEndpoints[event.Path] && event.StatusCode == 200 && !profile.HadLoginFlow && profile.TotalRequests < 5 {
		penalty += 0.55
		reasons = append(reasons, fmt.Sprintf("auth_bypass_attempt:%s", event.Path))
	}

	return math.Min(penalty, 1.0), reasons, signals
}
