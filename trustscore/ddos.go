package trustscore

import (
	"fmt"
	"math"
)

var ExpensiveEndpoints = map[string]bool{
	"/search":              true,
	"/api/search":          true,
	"/export":              true,
	"/report":              true,
	"/api/export":          true,
	"/download/all":        true,
	"/api/report/generate": true,
	"/api/analytics":       true,
	"/admin/logs":          true,
}

func ScoreDDoS(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string) {
	penalty := 0.0
	var reasons []string

	burstCount := len(profile.BurstTimestamps)
	if burstCount > cfg.DDOSBurstHigh {
		penalty += 0.9
		reasons = append(reasons, fmt.Sprintf("burst:%dreq/s", burstCount))
	} else if burstCount > cfg.DDOSBurstMedium {
		penalty += 0.5
		reasons = append(reasons, fmt.Sprintf("high_burst:%dreq/s", burstCount))
	}

	rate60s := float64(len(profile.RecentTimestamps)) / 60.0
	if rate60s > cfg.DDOSRateHigh {
		penalty += 0.7
		reasons = append(reasons, fmt.Sprintf("sustained_rate:%.1freq/s", rate60s))
	} else if rate60s > cfg.DDOSRateMedium {
		penalty += 0.35
		reasons = append(reasons, fmt.Sprintf("elevated_rate:%.1freq/s", rate60s))
	}

	if ExpensiveEndpoints[event.Path] {
		recent := slidingWindowCount(profile.EndpointTimestamps[event.Path], 60, event.Timestamp)
		if recent > cfg.DDOSExpensiveRate {
			penalty += 0.6
			reasons = append(reasons, fmt.Sprintf("expensive_endpoint_hammer:%s:%d/60s", event.Path, recent))
		}
	}

	if event.RequestSize > cfg.DDOSLargePayloadBytes {
		penalty += 0.3
		reasons = append(reasons, fmt.Sprintf("large_payload:%db", event.RequestSize))
	}

	return math.Min(penalty, 1.0), reasons
}
