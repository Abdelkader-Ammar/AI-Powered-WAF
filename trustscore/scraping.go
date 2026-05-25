package trustscore

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

var PaginationPattern = regexp.MustCompile(`[?&](page|p|offset|start|from)=(\d+)`)

func ScoreScraping(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string, ScrapingSignals) {
	penalty := 0.0
	var reasons []string
	var signals ScrapingSignals

	pageMatch := PaginationPattern.FindStringSubmatch(event.QueryString)
	if pageMatch != nil {
		basePath := event.Path
		pageNum, err := strconv.Atoi(pageMatch[2])
		if err == nil {
			signals.PaginationPath = basePath
			signals.PageNumber = pageNum

			pageCount := len(profile.PaginationSequences[basePath]) + 1
			if pageCount > cfg.ScrapePaginationHigh {
				penalty += 0.5
				reasons = append(reasons, fmt.Sprintf("pagination_scrape:%s:%d_pages", basePath, pageCount))
			} else if pageCount > cfg.ScrapePaginationMedium {
				penalty += 0.25
				reasons = append(reasons, fmt.Sprintf("pagination_elevated:%s:%d_pages", basePath, pageCount))
			}
		}
	}

	if profile.TotalRequests >= 20 {
		successRate := 0.0
		if profile.TotalRequests > 0 {
			successRate = float64(profile.Total200) / float64(profile.TotalRequests)
		}
		if successRate > 0.9 && len(profile.UniqueEndpoints) > 30 {
			penalty += 0.4
			reasons = append(reasons, fmt.Sprintf("bulk_resource_download:success_rate=%.0f%%", successRate*100))
		}
	}

	if profile.NonAssetRequestCount >= 10 && profile.AssetRequestCount == 0 {
		penalty += 0.45
		reasons = append(reasons, "no_asset_requests:likely_headless_client")
	}

	total := profile.AssetRequestCount + profile.NonAssetRequestCount
	if total >= 20 {
		assetRatio := float64(profile.AssetRequestCount) / float64(total)
		if assetRatio < 0.1 {
			penalty += 0.3
			reasons = append(reasons, fmt.Sprintf("low_asset_ratio:%.0f%%", assetRatio*100))
		}
	}

	if len(profile.RecentTimestamps) >= 10 {
		cv := coefficientOfVariation(profile.RecentTimestamps)
		if cv < cfg.ScrapeCVThreshold {
			penalty += 0.35
			reasons = append(reasons, fmt.Sprintf("robot_timing:CV=%.3f", cv))
		}
	}

	return math.Min(penalty, 1.0), reasons, signals
}
