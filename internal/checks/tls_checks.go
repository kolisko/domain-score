package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type TLSCertificateValid struct{}
type TLSExpiry struct{}
type TLSModernVersion struct{}
type TLSHostname struct{}
type TLSChain struct{}
type TLSALPN struct{}

func (TLSCertificateValid) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "tls.certificate_valid", Title: "TLS certifikát je dostupný", Category: "tls", Mode: audit.ModeSafe, Weight: 6, Severity: audit.SeverityCritical, Tags: []string{"tls", "https"}}
}
func (c TLSCertificateValid) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !ev.TLS.Presented {
		return fail(c.Meta(), map[string]any{"error": ev.TLS.Error}, "Nasaďte platný TLS certifikát pro HTTPS.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"issuer": ev.TLS.Issuer, "subject": ev.TLS.Subject}, "")
}

func (TLSExpiry) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "tls.expiry", Title: "TLS certifikát neexpiruje brzy", Category: "tls", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"tls"}}
}
func (c TLSExpiry) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !ev.TLS.Presented {
		return fail(c.Meta(), nil, "Nejdřív opravte dostupnost TLS certifikátu.", c.Meta().Weight)
	}
	if ev.TLS.DaysUntilExpiry < 0 {
		return fail(c.Meta(), map[string]any{"not_after": ev.TLS.NotAfter}, "Obnovte expirovaný TLS certifikát.", c.Meta().Weight)
	}
	if ev.TLS.DaysUntilExpiry < 30 {
		return warn(c.Meta(), map[string]any{"days_until_expiry": ev.TLS.DaysUntilExpiry}, "Obnovte certifikát s dostatečným předstihem.", 3)
	}
	return pass(c.Meta(), map[string]any{"days_until_expiry": ev.TLS.DaysUntilExpiry}, "")
}

func (TLSModernVersion) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "tls.modern_version", Title: "Moderní TLS verze", Category: "tls", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"tls"}}
}
func (c TLSModernVersion) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.TLS.Version == "" {
		return fail(c.Meta(), nil, "Ověřte TLS konfiguraci a povolte TLS 1.2 nebo TLS 1.3.", c.Meta().Weight)
	}
	if ev.TLS.Version != "TLS 1.3" && ev.TLS.Version != "TLS 1.2" {
		return fail(c.Meta(), map[string]any{"version": ev.TLS.Version}, "Vypněte staré TLS protokoly a ponechte TLS 1.2/1.3.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"version": ev.TLS.Version, "cipher_suite": ev.TLS.CipherSuite}, "")
}

func (TLSHostname) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "tls.hostname", Title: "Certifikát pokrývá hostname", Category: "tls", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityCritical, Tags: []string{"tls"}}
}
func (c TLSHostname) Run(_ context.Context, target audit.Target, ev audit.SharedEvidence) audit.Result {
	if !ev.TLS.VerifiedHostname {
		return fail(c.Meta(), map[string]any{"domain": target.Domain, "dns_names": ev.TLS.DNSNames}, "Vystavte certifikát, který obsahuje auditovaný hostname v SAN.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"dns_names": ev.TLS.DNSNames}, "")
}

func (TLSChain) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "tls.chain", Title: "TLS chain je kompletní", Category: "tls", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"tls"}}
}
func (c TLSChain) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.TLS.ChainLength == 0 {
		return fail(c.Meta(), nil, "Publikujte kompletní certifikační chain včetně intermediates.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"chain_length": ev.TLS.ChainLength}, "")
}

func (TLSALPN) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "tls.alpn", Title: "HTTP/2 nebo HTTP/3 signál", Category: "tls", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"tls", "performance"}}
}
func (c TLSALPN) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !strings.Contains(ev.TLS.ALPN, "h2") && !strings.Contains(ev.TLS.ALPN, "h3") {
		return warn(c.Meta(), map[string]any{"alpn": ev.TLS.ALPN}, "Povolte HTTP/2 nebo HTTP/3 pro lepší výkon.", 1)
	}
	return pass(c.Meta(), map[string]any{"alpn": ev.TLS.ALPN}, "")
}
