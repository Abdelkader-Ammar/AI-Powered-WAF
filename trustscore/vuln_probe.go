package trustscore

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func ScoreVulnProbe(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string, VulnProbeSignals) {
	penalty := 0.0
	var reasons []string
	var signals VulnProbeSignals

	baseKey := extractBaseParam(event.Path, event.QueryString)
	if baseKey != "" {
		paramVal := extractLastParamValue(event.QueryString)
		signals.ParamFuzzing = true
		signals.ParamFuzzingBase = baseKey
		signals.ParamFuzzingVal = paramVal

		seq := profile.ParamFuzzingSequences[baseKey]
		seqLen := len(seq) + 1
		tempSeq := make([]string, len(seq), len(seq)+1)
		copy(tempSeq, seq)
		tempSeq = append(tempSeq, paramVal)
		if isIncrementalSequence(tempSeq) && seqLen >= cfg.VulnFuzzMinSeq {
			penalty += 0.55
			reasons = append(reasons, fmt.Sprintf("param_fuzzing:%s:%d_mutations", baseKey, seqLen))
		}
	}

	if event.StatusCode == 500 {
		signals.Repeated500 = true
		signals.Repeated500Path = event.Path

		count := profile.Repeated500Endpoints[event.Path] + 1
		if count >= cfg.Vuln500High {
			penalty += 0.7
			reasons = append(reasons, fmt.Sprintf("repeated_500:%s:%dx", event.Path, count))
		} else if count >= cfg.Vuln500Medium {
			penalty += 0.4
			reasons = append(reasons, fmt.Sprintf("multiple_500:%s:%dx", event.Path, count))
		}
	}

	optionsCount := 0
	for _, methods := range profile.EndpointMethods {
		if methods["OPTIONS"] {
			optionsCount++
		}
	}
	if optionsCount >= cfg.VulnOptionsFlood {
		penalty += 0.4
		reasons = append(reasons, fmt.Sprintf("options_flood:%d_endpoints", optionsCount))
	}

	return math.Min(penalty, 1.0), reasons, signals
}

func extractBaseParam(path, queryString string) string {
	if queryString == "" {
		return ""
	}
	parts := strings.Split(queryString, "&")
	if len(parts) == 0 {
		return ""
	}
	firstParam := strings.Split(parts[0], "=")[0]
	return path + "?" + firstParam + "="
}

func extractLastParamValue(queryString string) string {
	if queryString == "" {
		return ""
	}
	parts := strings.Split(queryString, "&")
	if len(parts) == 0 {
		return ""
	}
	valueParts := strings.Split(parts[0], "=")
	if len(valueParts) > 1 {
		return valueParts[1]
	}
	return ""
}

func isIncrementalSequence(values []string) bool {
	if len(values) < 4 {
		return false
	}

	recent := values
	if len(recent) > 5 {
		recent = recent[len(recent)-5:]
	}

	nums := []int{}
	for _, v := range recent {
		num, err := strconv.Atoi(v)
		if err == nil {
			nums = append(nums, num)
		}
	}

	if len(nums) > 1 {
		diffs := []int{}
		for i := 0; i < len(nums)-1; i++ {
			diffs = append(diffs, nums[i+1]-nums[i])
		}

		if len(diffs) > 0 {
			allSame := true
			for i := 1; i < len(diffs); i++ {
				if diffs[i] != diffs[0] {
					allSame = false
					break
				}
			}
			if allSame {
				return true
			}
		}
	}

	lengths := []int{}
	for _, v := range recent {
		lengths = append(lengths, len(v))
	}

	if len(lengths) > 1 {
		lengthDiffs := []int{}
		for i := 0; i < len(lengths)-1; i++ {
			lengthDiffs = append(lengthDiffs, lengths[i+1]-lengths[i])
		}

		if len(lengthDiffs) > 0 {
			allSame := true
			allPositive := lengthDiffs[0] > 0
			for i := 0; i < len(lengthDiffs); i++ {
				if lengthDiffs[i] != lengthDiffs[0] || lengthDiffs[i] <= 0 {
					allSame = false
					break
				}
			}
			if allSame && allPositive {
				return true
			}
		}
	}

	return false
}
