package trustscore

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
)

var sensitivePathsMap = map[string]bool{
	"/.env":                    true,
	"/.env.local":              true,
	"/.env.production":         true,
	"/.env.backup":             true,
	"/config.php":              true,
	"/config.yml":              true,
	"/config.yaml":             true,
	"/configuration.php":       true,
	"/wp-config.php":           true,
	"/app/config/database.yml": true,
	"/.git":        true,
	"/.git/config": true,
	"/.git/HEAD":   true,
	"/.svn":        true,
	"/.hg":         true,
	"/admin":           true,
	"/admin/":          true,
	"/administrator":   true,
	"/wp-admin":        true,
	"/wp-admin/":       true,
	"/phpmyadmin":      true,
	"/pma":             true,
	"/adminer.php":     true,
	"/cpanel":          true,
	"/backup.zip":        true,
	"/backup.sql":        true,
	"/db.sql":            true,
	"/database.sql":      true,
	"/backup.tar.gz":     true,
	"/site.zip":          true,
	"/vendor":          true,
	"/node_modules":    true,
	"/.DS_Store":       true,
	"/actuator":        true,
	"/actuator/env":    true,
	"/actuator/health": true,
	"/__debug__":       true,
	"/debug":           true,
	"/console":         true,
	"/id_rsa":        true,
	"/.ssh/id_rsa":   true,
	"/private.key":   true,
	"/etc/passwd":       true,
	"/etc/shadow":       true,
	"/proc/self/environ": true,
	"/api/v1/admin": true,
	"/api/admin":    true,
	"/api/internal": true,
	"/graphql":      true,
}

var idPattern = regexp.MustCompile(`^(.*?)(\d+)([^/]*)$`)

type IDProbe struct {
	Base           string
	SequenceLength int
}

func ScoreRecon(profile *IPProfile, path string, now float64, cfg Config) (float64, []string, ReconSignals) {
	penalty := 0.0
	var reasons []string
	var signals ReconSignals

	totalRequests := profile.TotalRequests
	total404 := profile.Total404
	total403 := profile.Total403

	// High 404 rate
	if totalRequests >= 10 {
		rate404 := float64(total404) / float64(totalRequests)
		if rate404 > cfg.ReconHighRate404 {
			penalty += 0.5
			reasons = append(reasons, fmt.Sprintf("high_404_rate:%.0f%%", rate404*100))
		} else if rate404 > cfg.ReconMediumRate404 {
			penalty += 0.25
			reasons = append(reasons, fmt.Sprintf("medium_404_rate:%.0f%%", rate404*100))
		}
	}

	// High 403 rate
	if totalRequests >= 10 {
		rate403 := float64(total403) / float64(totalRequests)
		if rate403 > cfg.ReconHighRate403 {
			penalty += 0.4
			reasons = append(reasons, fmt.Sprintf("high_403_rate:%.0f%%", rate403*100))
		}
	}

	// Sensitive path hit
	if sensitivePathsMap[path] {
		hitCount := len(profile.SensitivePathHits) + 1
		signals.SensitivePathHit = true
		signals.SensitiveHit = SensitiveHit{Path: path, Timestamp: now}
		if hitCount == 1 {
			penalty += 0.6
			reasons = append(reasons, fmt.Sprintf("sensitive_path_hit:%s", path))
		} else {
			penaltyAdd := math.Min(0.6+0.1*float64(hitCount-1), 1.0)
			penalty += penaltyAdd
			reasons = append(reasons, fmt.Sprintf("sensitive_path_hit:%s (total:%d)", path, hitCount))
		}
	}

	// Sequential ID enumeration
	probe, newNum, baseKey := detectIDSequence(profile, path)
	signals.NewNumericID = newNum
	signals.IDSequenceBasePath = baseKey
	if probe != nil {
		if probe.SequenceLength >= cfg.IDEnumMinSequence {
			severity := math.Min(float64(probe.SequenceLength-5)/20, 1.0)
			penalty += 0.3 + 0.5*severity
			reasons = append(reasons, fmt.Sprintf("id_enumeration:%s (%d sequential IDs)", probe.Base, probe.SequenceLength))
		}
	}

	// HTTP method probing
	methods := profile.EndpointMethods[path]
	if len(methods) >= cfg.MethodProbeMin {
		penalty += 0.4
		var methodList []string
		for m := range methods {
			methodList = append(methodList, m)
		}
		reasons = append(reasons, fmt.Sprintf("method_probing:%s methods=%v", path, methodList))
	}

	// Endpoint diversity explosion
	// Require at least 10 requests and 30 seconds of session age to avoid
	// false positives on the very first request (division by near-zero time).
	if profile.TotalRequests >= 10 {
		sessionAgeSec := now - profile.FirstSeen
		if sessionAgeSec >= 30 {
			sessionAgeMin := sessionAgeSec / 60
			endpointsPerMin := float64(len(profile.UniqueEndpoints)) / sessionAgeMin
			if endpointsPerMin > cfg.EndpointDiversityThreshold {
				penalty += 0.5
				reasons = append(reasons, fmt.Sprintf("endpoint_explosion:%.1f/min", endpointsPerMin))
			}
		}
	}

	// Robots.txt / sitemap crawl
	pages := profile.PagesVisited
	if len(pages) >= 2 {
		if pages[0] == "/robots.txt" || pages[0] == "/sitemap.xml" {
			penalty += 0.3
			reasons = append(reasons, "robots_sitemap_followed_by_scan")
		}
	}

	return math.Min(penalty, 1.0), reasons, signals
}

func detectIDSequence(profile *IPProfile, path string) (*IDProbe, int, string) {
	match := idPattern.FindStringSubmatch(path)
	if len(match) == 0 {
		return nil, 0, ""
	}

	base := match[1]
	numberStr := match[2]
	number, err := strconv.Atoi(numberStr)
	if err != nil {
		return nil, 0, ""
	}

	// Read-only: compute what the sequence would look like without mutating
	seq := profile.NumericIDSequences[base]
	tempSeq := make([]int, len(seq)+1)
	copy(tempSeq, seq)
	tempSeq[len(seq)] = number
	tempSeq = removeDuplicatesAndSort(tempSeq)

	if len(tempSeq) < 3 {
		return nil, number, base
	}

	consecutive := 1
	for i := len(tempSeq) - 1; i > 0; i-- {
		if tempSeq[i]-tempSeq[i-1] == 1 {
			consecutive++
		} else {
			break
		}
	}

	if consecutive >= 3 {
		return &IDProbe{
			Base:           base,
			SequenceLength: consecutive,
		}, number, base
	}
	return nil, number, base
}

func removeDuplicatesAndSort(nums []int) []int {
	seen := make(map[int]bool)
	var result []int
	for _, n := range nums {
		if !seen[n] {
			seen[n] = true
			result = append(result, n)
		}
	}
	sort.Ints(result)
	return result
}
