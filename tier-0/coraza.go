package main

import (
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type CorazaWAF struct {
	waf coraza.WAF
}

func NewCorazaWAF(rulesPath string) (*CorazaWAF, error) {
	var waf coraza.WAF
	var err error

	if rulesPath == "crs" {
		waf, err = coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(strings.Join(crsDirectives(), "\n")))
	} else {
		waf, err = coraza.NewWAF(coraza.NewWAFConfig().
			WithDirectivesFromFile(rulesPath))
	}

	if err != nil {
		return nil, err
	}
	return &CorazaWAF{waf: waf}, nil
}

// crsDirectives generates Include directives for all embedded CRS rule files.
func crsDirectives() []string {
	dirs := []string{
		"Include @coraza.conf-recommended",
		"SecRuleEngine On",
	}
	entries, err := fs.ReadDir(coreruleset.FS, "@owasp_crs")
	if err != nil {
		log.Printf("[WARN] Failed to read CRS rules directory: %v", err)
		return dirs
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".conf") {
			dirs = append(dirs, "Include @owasp_crs/"+e.Name())
		}
	}
	return dirs
}

func (c *CorazaWAF) ProcessRequest(r *http.Request) (allowed bool, status int, err error) {
	tx := c.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessConnection("", 0, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vr := range r.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return false, statusCodeFromInterruption(it), nil
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return false, http.StatusBadRequest, err
		}
		if it != nil {
			return false, statusCodeFromInterruption(it), nil
		}

		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return false, http.StatusInternalServerError, err
		}
		r.Body = io.NopCloser(io.MultiReader(rbr, r.Body))
	}

	it, err := tx.ProcessRequestBody()
	if it != nil {
		return false, statusCodeFromInterruption(it), nil
	}
	return true, http.StatusOK, err
}

func statusCodeFromInterruption(it *types.Interruption) int {
	if it.Action == "deny" && it.Status != 0 {
		return it.Status
	}
	return http.StatusForbidden
}

func initCorazaWAF(proxy *WAFProxy) {
	if !LiveConfig.EnableCoraza {
		proxy.Coraza = nil
		log.Printf("[INFO] Coraza disabled by config")
		return
	}

	waf, err := NewCorazaWAF(LiveConfig.CorazaRulesPath)
	if err != nil {
		log.Printf("[WARN] Coraza initialization failed: %v. Running without Coraza.", err)
		proxy.Coraza = nil
		return
	}

	proxy.Coraza = waf
	log.Printf("[INFO] Coraza WAF active: %s", LiveConfig.CorazaRulesPath)
}
