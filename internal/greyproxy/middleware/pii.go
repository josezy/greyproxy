package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/greyhavenhq/greyproxy/internal/gostx"
)

// PIIConfig holds configuration for the PII middleware.
type PIIConfig struct {
	Enabled   bool
	Action    string // "redact" or "block"
	Types     map[string]bool
	Allowlist []string
}

// PIIScanResult contains the result of a PII scan.
type PIIScanResult struct {
	RedactedBody []byte
	MatchCount   int
	TypeLabels   []string // deduplicated list, e.g. ["email", "ssn"]
	Blocked      bool     // true when Action is "block" and PII was found
}

// PIIMiddleware scans and redacts PII from request bodies.
// It plugs into the global hook pipeline as an in-process middleware.
type PIIMiddleware struct {
	mu        sync.RWMutex
	enabled   bool
	action    string
	patterns  []piiPattern
	allowlist map[string]struct{}
}

type piiPattern struct {
	name     string
	re       *regexp.Regexp
	validate func(match string) bool // optional post-match validation
}

const maxPIIBodySize = 10 * 1024 * 1024 // 10MB

// NewPIIMiddleware creates a new PII middleware with the given config.
func NewPIIMiddleware(cfg PIIConfig) *PIIMiddleware {
	m := &PIIMiddleware{}
	m.updateInternal(cfg)
	return m
}

// UpdateConfig rebuilds compiled regexes and allowlist from new config.
func (m *PIIMiddleware) UpdateConfig(cfg PIIConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateInternal(cfg)
}

func (m *PIIMiddleware) updateInternal(cfg PIIConfig) {
	m.enabled = cfg.Enabled
	m.action = cfg.Action
	if m.action == "" {
		m.action = "redact"
	}

	m.allowlist = make(map[string]struct{}, len(cfg.Allowlist))
	for _, v := range cfg.Allowlist {
		m.allowlist[v] = struct{}{}
	}

	m.patterns = nil

	types := cfg.Types
	if types == nil {
		types = map[string]bool{
			"email":       true,
			"phone":       true,
			"ssn":         true,
			"credit_card": true,
			"ip_address":  true,
		}
	}

	if types["email"] {
		m.patterns = append(m.patterns, piiPattern{
			name: "EMAIL",
			re:   regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		})
	}
	if types["ssn"] {
		m.patterns = append(m.patterns, piiPattern{
			name: "SSN",
			re:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		})
	}
	if types["phone"] {
		m.patterns = append(m.patterns, piiPattern{
			name: "PHONE",
			re:   regexp.MustCompile(`\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b`),
		})
	}
	if types["credit_card"] {
		m.patterns = append(m.patterns, piiPattern{
			name:     "CREDIT_CARD",
			re:       regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			validate: luhnValid,
		})
	}
	if types["ip_address"] {
		m.patterns = append(m.patterns, piiPattern{
			name:     "IP_ADDRESS",
			re:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
			validate: isPublicIP,
		})
	}
}

// ScanAndRedact scans the body for PII and returns the redacted result.
// Returns nil if the filter is disabled or no scanning needed.
func (m *PIIMiddleware) ScanAndRedact(body []byte, contentType string) *PIIScanResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return nil
	}

	// Fast-path skips
	if len(body) == 0 {
		return nil
	}
	if len(body) > maxPIIBodySize {
		return nil
	}
	if !piiIsTextContentType(contentType) {
		return nil
	}

	text := string(body)
	counters := make(map[string]int)
	typeSeen := make(map[string]bool)
	totalMatches := 0

	for _, pat := range m.patterns {
		matches := pat.re.FindAllStringIndex(text, -1)
		if len(matches) == 0 {
			continue
		}

		// Process matches in reverse order to preserve indices
		for i := len(matches) - 1; i >= 0; i-- {
			start, end := matches[i][0], matches[i][1]
			matched := text[start:end]

			// Check allowlist
			if _, ok := m.allowlist[matched]; ok {
				continue
			}

			// Run validation if present
			if pat.validate != nil && !pat.validate(matched) {
				continue
			}

			counters[pat.name]++
			totalMatches++
			typeSeen[pat.name] = true

			if m.action == "redact" {
				placeholder := fmt.Sprintf("[PII_%s_%d]", pat.name, counters[pat.name])
				text = text[:start] + placeholder + text[end:]
			}
		}
	}

	if totalMatches == 0 {
		return nil
	}

	// Build deduplicated type labels (lowercase for storage)
	var typeLabels []string
	for t := range typeSeen {
		typeLabels = append(typeLabels, strings.ToLower(t))
	}

	if m.action == "block" {
		return &PIIScanResult{
			MatchCount: totalMatches,
			TypeLabels: typeLabels,
			Blocked:    true,
		}
	}

	return &PIIScanResult{
		RedactedBody: []byte(text),
		MatchCount:   totalMatches,
		TypeLabels:   typeLabels,
	}
}

// HandleMitmRequest is a hook adapter for the MITM request pipeline.
// It reads the request body, scans for PII, and either redacts (rewrites
// req.Body in place) or blocks (returns ErrRequestDenied).
func (m *PIIMiddleware) HandleMitmRequest(ctx context.Context, req *http.Request, containerName string) error {
	m.mu.RLock()
	enabled := m.enabled
	m.mu.RUnlock()
	if !enabled {
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	ct := req.Header.Get("Content-Type")
	result := m.ScanAndRedact(body, ct)
	if result == nil {
		return nil
	}

	if result.Blocked {
		return gostx.ErrRequestDenied
	}

	// Redact: replace the body
	req.Body = io.NopCloser(bytes.NewReader(result.RedactedBody))
	req.ContentLength = int64(len(result.RedactedBody))
	return nil
}

// HandleProxyRequest is a hook adapter for the plain HTTP request pipeline.
// It reads the request body, scans for PII, and returns a ProxyRequestDecision
// (deny with 403 on block, rewrite on redact, nil on allow/no-match).
func (m *PIIMiddleware) HandleProxyRequest(ctx context.Context, req *http.Request, containerName string) *gostx.ProxyRequestDecision {
	m.mu.RLock()
	enabled := m.enabled
	m.mu.RUnlock()
	if !enabled {
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	ct := req.Header.Get("Content-Type")
	result := m.ScanAndRedact(body, ct)
	if result == nil {
		return nil
	}

	if result.Blocked {
		return &gostx.ProxyRequestDecision{
			Deny:       true,
			StatusCode: 403,
			DenyBody:   "Request blocked: PII detected",
		}
	}

	// Redact: rewrite the body
	return &gostx.ProxyRequestDecision{
		NewBody: result.RedactedBody,
	}
}

// luhnValid performs the Luhn algorithm check on a credit card number string.
func luhnValid(s string) bool {
	// Strip spaces and dashes
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// isPublicIP returns true if the IP is not in a private/reserved range.
func isPublicIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	a, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	b, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	// 10.x.x.x
	if a == 10 {
		return false
	}
	// 172.16.0.0 - 172.31.255.255
	if a == 172 && b >= 16 && b <= 31 {
		return false
	}
	// 192.168.x.x
	if a == 192 && b == 168 {
		return false
	}
	// 127.x.x.x (loopback)
	if a == 127 {
		return false
	}
	// 0.x.x.x
	if a == 0 {
		return false
	}
	// 169.254.x.x (link-local)
	if a == 169 && b == 254 {
		return false
	}

	return true
}

// piiIsTextContentType checks if a content type is text-based.
func piiIsTextContentType(ct string) bool {
	if ct == "" {
		return true // Assume text if not specified
	}
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	switch {
	case strings.HasPrefix(ct, "text/"):
		return true
	case ct == "application/json",
		ct == "application/xml",
		ct == "application/x-www-form-urlencoded",
		ct == "application/graphql",
		ct == "application/javascript",
		ct == "application/x-javascript":
		return true
	case strings.HasSuffix(ct, "+json"),
		strings.HasSuffix(ct, "+xml"):
		return true
	}
	return false
}
