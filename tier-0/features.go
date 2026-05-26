package main

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/corazawaf/libinjection-go"
)

const ExpectedEngineeredFeatures = 42

var (
	sqlKeywordsPattern    = regexp.MustCompile(`(?i)\b(select|union|insert|update|delete|drop|alter|create|where|having|order\s+by|group\s+by)\b`)
	scriptTagsPattern     = regexp.MustCompile(`(?i)(<script|javascript:|onerror=|onload=|eval\(|alert\()`)
	traversalPattern      = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)`)
	ssrfPattern           = regexp.MustCompile(`(?i)(127\.0\.0\.1|localhost|169\.254|file://|dict://|gopher://)`)
	sstiPattern           = regexp.MustCompile(`(\{\{|\$\{|<%|#\{)`)
	crlfPattern           = regexp.MustCompile(`(?i)(\r\n|%0d%0a)`)
	hostIsIPPattern       = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$`)
	unicodeEscapePattern  = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	csrfPattern           = regexp.MustCompile(`(?i)(csrf|xsrf|token)`) // Fallback, will check actual implementation

	specialChars     = `'";|%<>()`
	bodySpecialChars = "'\";|%<>()\\{}$\\`"
	whitespaceChars  = " \t\n\r\v\f\xc2\xa0"

	riskyExts = map[string]bool{
		".php": true, ".asp": true, ".jsp": true, ".cgi": true,
		".sh": true, ".py": true, ".pl": true,
	}
)

func entropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var ent float64
	for _, c := range counts {
		p := float64(c) / float64(len(s))
		ent -= p * math.Log2(p)
	}
	return ent
}

func countChars(s, chars string) int {
	count := 0
	for _, r := range s {
		if strings.ContainsRune(chars, r) {
			count++
		}
	}
	return count
}

func tryUnescape(s string) string {
	if unescaped, err := url.QueryUnescape(s); err == nil {
		return unescaped
	}
	return s
}

func getDepth(s string) int {
	return strings.Count(s, "/")
}

// ExtractFeatures extracts the 42 engineered features from an HTTP request
func ExtractFeatures(req *http.Request, bodyBytes []byte) []float64 {
	features := make([]float64, ExpectedEngineeredFeatures)

	// Validate output size matches training expectation
	if len(features) != ExpectedEngineeredFeatures {
		log.Printf("[WARN] Feature vector size mismatch: got %d, expected %d", len(features), ExpectedEngineeredFeatures)
	}

	// Pre-process body
	bodyStr := string(bodyBytes)
	bodyLen := len(bodyBytes)

	// Pre-process URL and Query
	path := req.URL.Path
	query := req.URL.RawQuery
	fullURL := path
	if query != "" {
		fullURL += "?" + query
	}
	urlLen := len(fullURL)
	if urlLen == 0 {
		urlLen = 1 // Prevent division by zero
	}

	// 1. body_compression_ratio
	features[0] = 1.0
	if bodyLen > 0 {
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		w.Write(bodyBytes)
		w.Close()
		features[0] = float64(buf.Len()) / float64(bodyLen)
	}

	// 2. body_entropy
	features[1] = entropy(bodyStr)

	// 3. body_has_script_tags
	if scriptTagsPattern.MatchString(bodyStr) {
		features[2] = 1.0
	}

	// 4. body_has_sql_keywords
	if sqlKeywordsPattern.MatchString(bodyStr) {
		features[3] = 1.0
	}

	// 5. body_has_traversal_pattern
	if traversalPattern.MatchString(bodyStr) {
		features[4] = 1.0
	}

	// 6. body_has_unicode_escape
	if unicodeEscapePattern.MatchString(bodyStr) {
		features[5] = 1.0
	}

	// 7. body_is_json
	isJSON := false
	if len(bodyStr) > 0 && (bodyStr[0] == '{' || bodyStr[0] == '[') {
		if json.Valid(bodyBytes) {
			isJSON = true
			features[6] = 1.0
		}
	}

	// 8. body_is_xml
	if len(bodyStr) >= 5 && strings.HasPrefix(strings.ToLower(bodyStr[:5]), "<?xml") {
		features[7] = 1.0
	}

	// 9. body_length
	features[8] = float64(bodyLen)

	// 10. body_pct_encoded_chars
	if bodyLen > 0 {
		features[9] = float64(strings.Count(bodyStr, "%")) / float64(bodyLen)
	}

	// 11. body_pct_special_chars
	if bodyLen > 0 {
		features[10] = float64(countChars(bodyStr, bodySpecialChars)) / float64(bodyLen)
	}

	// 12. content_type_mismatch
	contentType := req.Header.Get("Content-Type")
	if isJSON && !strings.Contains(strings.ToLower(contentType), "application/json") {
		features[11] = 1.0
	}

	// 13. cookie_count
	cookieHeader := req.Header.Get("Cookie")
	if cookieHeader != "" {
		features[12] = float64(strings.Count(cookieHeader, ";") + 1)
	}

	// 14. encoding_layers_detected
	layers := 0
	current := fullURL
	for {
		unescaped := tryUnescape(current)
		if unescaped == current || layers > 10 {
			break
		}
		layers++
		current = unescaped
	}
	features[13] = float64(layers)

	// 15. has_backtick_in_query
	if strings.ContainsRune(query, '`') {
		features[14] = 1.0
	}

	// 16. has_crlf_injection
	if crlfPattern.MatchString(fullURL + cookieHeader) {
		features[15] = 1.0
	}

	// 17. has_csrf_pattern
	if csrfPattern.MatchString(cookieHeader + bodyStr) {
		features[16] = 1.0
	}

	// 18. has_double_encoding
	if strings.Contains(fullURL, "%25") {
		features[17] = 1.0
	}

	// 19. has_null_byte
	if strings.Contains(fullURL, "%00") || strings.ContainsRune(fullURL, '\x00') {
		features[18] = 1.0
	}

	// 20. has_pipe_in_query
	if strings.ContainsRune(query, '|') {
		features[19] = 1.0
	}

	// 21. has_semicolon_in_query
	if strings.ContainsRune(query, ';') {
		features[20] = 1.0
	}

	// 22. has_ssrf_pattern
	if ssrfPattern.MatchString(fullURL + bodyStr) {
		features[21] = 1.0
	}

	// 23. has_ssti_pattern
	if sstiPattern.MatchString(fullURL + bodyStr) {
		features[22] = 1.0
	}

	// 24. host_is_ip
	host := req.Host
	if hostIsIPPattern.MatchString(host) {
		features[23] = 1.0
	}

	// 25. json_key_count
	// 26. json_nesting_depth
	if isJSON {
		var parsedJSON interface{}
		if err := json.Unmarshal(bodyBytes, &parsedJSON); err == nil {
			var analyzeJSON func(v interface{}, depth int) (int, int)
			analyzeJSON = func(v interface{}, depth int) (keys int, maxDepth int) {
				maxDepth = depth
				switch val := v.(type) {
				case map[string]interface{}:
					keys += len(val)
					for _, child := range val {
						childKeys, childDepth := analyzeJSON(child, depth+1)
						keys += childKeys
						if childDepth > maxDepth {
							maxDepth = childDepth
						}
					}
				case []interface{}:
					for _, child := range val {
						childKeys, childDepth := analyzeJSON(child, depth+1)
						keys += childKeys
						if childDepth > maxDepth {
							maxDepth = childDepth
						}
					}
				}
				return
			}
			keys, depth := analyzeJSON(parsedJSON, 1)
			features[24] = float64(keys)
			features[25] = float64(depth)
		}
	}

	// 27. libinjection_sqli
	libinjSqliStr := fullURL + bodyStr
	if isSqli, _ := libinjection.IsSQLi(libinjSqliStr); isSqli {
		features[26] = 1.0
	}

	// 28. libinjection_xss
	if isXss := libinjection.IsXSS(fullURL + bodyStr); isXss {
		features[27] = 1.0
	}

	// 29. param_count
	// 30. param_max_val_length
	// 31. param_val_entropy_max
	parsedQuery := req.URL.Query()
	features[28] = float64(len(parsedQuery))
	maxValLen := 0
	maxValEntropy := 0.0
	for _, vals := range parsedQuery {
		for _, val := range vals {
			l := len(val)
			if l > maxValLen {
				maxValLen = l
			}
			ent := entropy(val)
			if ent > maxValEntropy {
				maxValEntropy = ent
			}
		}
	}
	features[29] = float64(maxValLen)
	features[30] = maxValEntropy

	// 32. path_file_extension_risky
	idx := strings.LastIndex(path, ".")
	if idx != -1 {
		ext := strings.ToLower(path[idx:])
		if riskyExts[ext] {
			features[31] = 1.0
		}
	}

	// 33. path_has_traversal_pattern
	if traversalPattern.MatchString(path) {
		features[32] = 1.0
	}

	// 34. pct_encoded_chars
	features[33] = float64(strings.Count(fullURL, "%")) / float64(urlLen)

	// 35. pct_special_chars
	features[34] = float64(countChars(fullURL, specialChars)) / float64(urlLen)

	// 36. query_entropy
	features[35] = entropy(query)

	// 37. query_has_script_tags
	if scriptTagsPattern.MatchString(query) {
		features[36] = 1.0
	}

	// 38. query_has_sql_keywords
	if sqlKeywordsPattern.MatchString(query) {
		features[37] = 1.0
	}

	// 39. request_line_is_malformed
	// We are acting as a proxy, if we got this far the standard library parsed it, 
	// but we can check if Method is completely weird
	method := req.Method
	isValidMethod := method == "GET" || method == "POST" || method == "PUT" || method == "DELETE" || method == "HEAD" || method == "OPTIONS" || method == "PATCH" || method == "TRACE"
	if !isValidMethod || strings.Contains(method, "GET-GET") { // Approximation
		features[38] = 1.0
	}

	// 40. url_depth
	features[39] = float64(getDepth(path))

	// 41. url_length
	features[40] = float64(urlLen)

	// 42. whitespace_variant_count
	whitespaceTypes := 0
	targetStr := query + bodyStr
	for _, c := range whitespaceChars {
		if strings.ContainsRune(targetStr, c) {
			whitespaceTypes++
		}
	}
	features[41] = float64(whitespaceTypes)

	return features
}
