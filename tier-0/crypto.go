package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// generateClearanceToken creates an HMAC-signed challenge clearance token.
// Format: salt:nonce:signature
func generateClearanceToken(salt, nonce string, secret []byte) string {
	payload := salt + ":" + nonce
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))
	return payload + ":" + signature
}

// verifyClearanceToken extracts and verifies the HMAC signature of a clearance token.
// Returns (salt, nonce, valid). The salt is self-contained (IP:YYYY-MM-DD) which
// enables /24 and /64 IP-binding checks without reconstructing state.
// MaxAge is enforced via date-string comparison (today or yesterday only),
// avoiding the midnight-boundary bug in time.Since().
func verifyClearanceToken(token string, secret []byte) (salt string, nonce string, valid bool) {
	lastColon := strings.LastIndex(token, ":")
	if lastColon < 0 {
		return
	}
	beforeSig := token[:lastColon]
	secondLastColon := strings.LastIndex(beforeSig, ":")
	if secondLastColon < 0 {
		return
	}

	nonce = beforeSig[secondLastColon+1:]
	salt = beforeSig[:secondLastColon]

	// MaxAge: accept today or yesterday only (date-string comparison avoids
	// midnight-boundary bug where time.Since() would expire tokens within
	// minutes of issuance for tokens issued near midnight).
	dateStr := salt[strings.LastIndex(salt, ":")+1:]
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	if dateStr != today && dateStr != yesterday {
		return
	}

	expected := generateClearanceToken(salt, nonce, secret)
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return
	}

	return salt, nonce, true
}

func ipv4Mask24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0"
}

func ipv6Mask64(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ""
	}
	mask := net.CIDRMask(64, 128)
	return parsed.Mask(mask).String()
}
