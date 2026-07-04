package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type HTTPHTTPSRedirect struct{}
type HTTPHSTS struct{}
type HTTPSecurityCSP struct{}
type HTTPSecurityNoSniff struct{}
type HTTPSecurityReferrerPolicy struct{}
type HTTPSecurityPermissionsPolicy struct{}
type HTTPSecurityFrameProtection struct{}
type HTTPSecurityIsolation struct{}
type HTTPSecurityCookieFlags struct{}
type HTTPSecurityServerLeakage struct{}
type HTTPSecurityCORS struct{}

func (HTTPHTTPSRedirect) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.https_redirect", Title: "HTTP přesměruje na HTTPS", Category: "http_security", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"https"}}
}
func (c HTTPHTTPSRedirect) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !ev.HTTP.RedirectedHTTPS {
		return fail(c.Meta(), map[string]any{"http_status": ev.HTTP.HTTPStatusCode}, "Přesměrujte veškerý HTTP provoz na HTTPS.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"http_status": ev.HTTP.HTTPStatusCode, "final_url": ev.HTTP.FinalURL}, "")
}

func (HTTPHSTS) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.hsts", Title: "HSTS header", Category: "http_security", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"headers", "https"}}
}
func (c HTTPHSTS) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	h := headerValue(ev.HTTP.Headers, "Strict-Transport-Security")
	if h == "" {
		return fail(c.Meta(), nil, "Přidejte `Strict-Transport-Security` s rozumným `max-age`.", c.Meta().Weight)
	}
	if !strings.Contains(strings.ToLower(h), "max-age=") {
		return warn(c.Meta(), map[string]any{"hsts": h}, "Doplňte `max-age` do HSTS headeru.", 2)
	}
	return pass(c.Meta(), map[string]any{"hsts": h}, "")
}

func (HTTPSecurityCSP) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.csp", Title: "Content-Security-Policy", Category: "http_security", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"headers", "xss"}}
}
func (c HTTPSecurityCSP) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	h := headerValue(ev.HTTP.Headers, "Content-Security-Policy")
	if h == "" {
		return fail(c.Meta(), nil, "Přidejte CSP politiku minimálně s `default-src` a bez zbytečně volného `unsafe-inline`.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"csp": h}, "")
}

func (HTTPSecurityNoSniff) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.x_content_type_options", Title: "X-Content-Type-Options", Category: "http_security", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityMedium, Tags: []string{"headers"}}
}
func (c HTTPSecurityNoSniff) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if strings.ToLower(headerValue(ev.HTTP.Headers, "X-Content-Type-Options")) != "nosniff" {
		return warn(c.Meta(), nil, "Nastavte `X-Content-Type-Options: nosniff`.", 1)
	}
	return pass(c.Meta(), map[string]any{"x_content_type_options": "nosniff"}, "")
}

func (HTTPSecurityReferrerPolicy) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.referrer_policy", Title: "Referrer-Policy", Category: "http_security", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"headers", "privacy"}}
}
func (c HTTPSecurityReferrerPolicy) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !hasHeader(ev.HTTP.Headers, "Referrer-Policy") {
		return warn(c.Meta(), nil, "Nastavte `Referrer-Policy`, například `strict-origin-when-cross-origin`.", 1)
	}
	return pass(c.Meta(), map[string]any{"referrer_policy": headerValue(ev.HTTP.Headers, "Referrer-Policy")}, "")
}

func (HTTPSecurityPermissionsPolicy) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.permissions_policy", Title: "Permissions-Policy", Category: "http_security", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"headers", "privacy"}}
}
func (c HTTPSecurityPermissionsPolicy) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !hasHeader(ev.HTTP.Headers, "Permissions-Policy") {
		return warn(c.Meta(), nil, "Omezte nepotřebná browser API přes `Permissions-Policy`.", 1)
	}
	return pass(c.Meta(), map[string]any{"permissions_policy": headerValue(ev.HTTP.Headers, "Permissions-Policy")}, "")
}

func (HTTPSecurityFrameProtection) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.frame_protection", Title: "Clickjacking ochrana", Category: "http_security", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"headers"}}
}
func (c HTTPSecurityFrameProtection) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	csp := strings.ToLower(headerValue(ev.HTTP.Headers, "Content-Security-Policy"))
	if strings.Contains(csp, "frame-ancestors") || hasHeader(ev.HTTP.Headers, "X-Frame-Options") {
		return pass(c.Meta(), map[string]any{"csp": csp, "x_frame_options": headerValue(ev.HTTP.Headers, "X-Frame-Options")}, "")
	}
	return warn(c.Meta(), nil, "Přidejte `frame-ancestors` do CSP nebo `X-Frame-Options`.", 2)
}

func (HTTPSecurityIsolation) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.cross_origin_isolation", Title: "Cross-origin isolation headers", Category: "http_security", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"headers"}}
}
func (c HTTPSecurityIsolation) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	missing := []string{}
	for _, h := range []string{"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"} {
		if !hasHeader(ev.HTTP.Headers, h) {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		return warn(c.Meta(), map[string]any{"missing": missing}, "Zvažte COOP/CORP/COEP podle typu aplikace.", 1)
	}
	return pass(c.Meta(), nil, "")
}

func (HTTPSecurityCookieFlags) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.cookie_flags", Title: "Cookie bezpečnostní flagy", Category: "http_security", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"cookies"}}
}
func (c HTTPSecurityCookieFlags) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.HTTP.Cookies) == 0 {
		return notApplicable(c.Meta(), nil, "Na hlavní stránce nebyly nastaveny cookies.")
	}
	bad := []string{}
	for _, cookie := range ev.HTTP.Cookies {
		if !cookie.Secure || !cookie.HttpOnly {
			bad = append(bad, cookie.Name)
		}
	}
	if len(bad) > 0 {
		return warn(c.Meta(), map[string]any{"cookies_missing_flags": bad}, "Cookies se session nebo citlivým stavem musí mít `Secure`, `HttpOnly` a vhodný `SameSite`.", 3)
	}
	return pass(c.Meta(), map[string]any{"cookies": len(ev.HTTP.Cookies)}, "")
}

func (HTTPSecurityServerLeakage) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.server_leakage", Title: "Server header neprozrazuje detaily", Category: "http_security", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"headers"}}
}
func (c HTTPSecurityServerLeakage) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	server := headerValue(ev.HTTP.Headers, "Server")
	powered := headerValue(ev.HTTP.Headers, "X-Powered-By")
	if powered != "" || strings.Count(server, "/") > 0 {
		return warn(c.Meta(), map[string]any{"server": server, "x_powered_by": powered}, "Omezte detailní server/framework bannery v hlavičkách.", 1)
	}
	return pass(c.Meta(), map[string]any{"server": server}, "")
}

func (HTTPSecurityCORS) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "http.cors_baseline", Title: "CORS není široce otevřené", Category: "http_security", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityHigh, Tags: []string{"cors"}}
}
func (c HTTPSecurityCORS) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	acao := headerValue(ev.HTTP.Headers, "Access-Control-Allow-Origin")
	if acao == "*" && strings.EqualFold(headerValue(ev.HTTP.Headers, "Access-Control-Allow-Credentials"), "true") {
		return fail(c.Meta(), map[string]any{"access_control_allow_origin": acao}, "Nepoužívejte wildcard CORS společně s credentials.", c.Meta().Weight)
	}
	if acao == "*" {
		return warn(c.Meta(), map[string]any{"access_control_allow_origin": acao}, "Omezte CORS wildcard jen na veřejná read-only API.", 1)
	}
	return pass(c.Meta(), map[string]any{"access_control_allow_origin": acao}, "")
}
