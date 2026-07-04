package netx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/miekg/dns"
	"golang.org/x/net/html"

	"github.com/kolisko/domain-score/internal/audit"
)

type Options struct {
	Aggressive bool
	Timeout    time.Duration
	UserAgent  string
}

func Collect(ctx context.Context, target audit.Target, opts Options) audit.SharedEvidence {
	if opts.Timeout == 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "domain-score/0.1 (+https://github.com/kolisko/domain-score)"
	}
	ev := audit.SharedEvidence{Errors: map[string]string{}}
	ev.DNS = collectDNS(target.Domain, opts.Timeout)
	ev.HTTP = collectHTTP(ctx, target.Domain, opts)
	ev.TLS = collectTLS(ctx, target.Domain, opts.Timeout)
	base := "https://" + target.Domain
	ev.Robots = fetchText(ctx, base+"/robots.txt", opts)
	ev.Sitemap = fetchText(ctx, base+"/sitemap.xml", opts)
	ev.LLMs = fetchText(ctx, base+"/llms.txt", opts)
	ev.SecurityText = fetchText(ctx, base+"/.well-known/security.txt", opts)
	ev.RDAP = collectRDAP(ctx, target.Domain, opts)
	ev.CT = collectCT(ctx, target.Domain, opts)
	ev.M365 = collectM365(ctx, target.Domain, ev.DNS, opts)
	ev.Reputation = collectReputation(ctx, target.Domain, opts)
	ev.External = collectExternal(ctx, target.Domain, ev.DNS, opts)
	if opts.Aggressive {
		ev.Aggressive = collectAggressive(ctx, target.Domain, ev, opts)
	}
	return ev
}

func collectDNS(domain string, timeout time.Duration) audit.DNSObservation {
	o := audit.DNSObservation{}
	for _, q := range []struct {
		name string
		t    uint16
	}{
		{domain, dns.TypeA},
		{domain, dns.TypeAAAA},
		{domain, dns.TypeNS},
		{domain, dns.TypeMX},
		{domain, dns.TypeTXT},
		{domain, dns.TypeCAA},
		{domain, dns.TypeSOA},
		{domain, dns.TypeDNSKEY},
		{domain, dns.TypeDS},
		{"_dmarc." + domain, dns.TypeTXT},
		{"_mta-sts." + domain, dns.TypeTXT},
		{"_smtp._tls." + domain, dns.TypeTXT},
		{"default._bimi." + domain, dns.TypeTXT},
		{"autodiscover." + domain, dns.TypeCNAME},
		{"www." + domain, dns.TypeA},
		{fmt.Sprintf("_domain-score-%d.%s", time.Now().UnixNano(), domain), dns.TypeA},
	} {
		msg, err := dnsQuery(q.name, q.t, timeout)
		if err != nil || msg == nil {
			continue
		}
		for _, ans := range msg.Answer {
			if h := ans.Header(); h != nil {
				updateTTL(&o, h.Ttl)
			}
			switch rr := ans.(type) {
			case *dns.A:
				if q.name == "www."+domain {
					o.WWWAddress = append(o.WWWAddress, rr.A.String())
				} else if strings.HasPrefix(q.name, "_domain-score-") {
					o.WildcardA = append(o.WildcardA, rr.A.String())
				} else {
					o.A = append(o.A, rr.A.String())
				}
			case *dns.AAAA:
				o.AAAA = append(o.AAAA, rr.AAAA.String())
			case *dns.NS:
				o.NS = append(o.NS, strings.TrimSuffix(rr.Ns, "."))
			case *dns.MX:
				o.MX = append(o.MX, fmt.Sprintf("%d %s", rr.Preference, strings.TrimSuffix(rr.Mx, ".")))
			case *dns.TXT:
				txt := strings.Join(rr.Txt, "")
				switch q.name {
				case "_dmarc." + domain:
					o.DMARCTXT = append(o.DMARCTXT, txt)
				case "_mta-sts." + domain:
					o.MTASTSTXT = append(o.MTASTSTXT, txt)
				case "_smtp._tls." + domain:
					o.TLSRPTTXT = append(o.TLSRPTTXT, txt)
				case "default._bimi." + domain:
					o.BIMITXT = append(o.BIMITXT, txt)
				default:
					o.TXT = append(o.TXT, txt)
					if strings.HasPrefix(strings.ToLower(txt), "ms=") {
						o.MSVerify = append(o.MSVerify, txt)
					}
				}
			case *dns.CNAME:
				if q.name == "autodiscover."+domain {
					o.Autodiscover = append(o.Autodiscover, strings.TrimSuffix(rr.Target, "."))
				}
			case *dns.CAA:
				o.CAA = append(o.CAA, fmt.Sprintf("%d %s %s", rr.Flag, rr.Tag, rr.Value))
			case *dns.SOA:
				o.SOA = append(o.SOA, rr.String())
			case *dns.DNSKEY:
				o.DNSKEY = append(o.DNSKEY, rr.String())
			case *dns.DS:
				o.DS = append(o.DS, rr.String())
			}
		}
	}
	sort.Strings(o.A)
	sort.Strings(o.AAAA)
	sort.Strings(o.NS)
	collectDKIM(domain, timeout, &o)
	return o
}

func collectDKIM(domain string, timeout time.Duration, o *audit.DNSObservation) {
	selectors := []string{"default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim", "mandrill", "sendgrid", "mailgun"}
	for _, selector := range selectors {
		name := selector + "._domainkey." + domain
		msg, err := dnsQuery(name, dns.TypeTXT, timeout)
		if err != nil || msg == nil {
			continue
		}
		for _, ans := range msg.Answer {
			rr, ok := ans.(*dns.TXT)
			if !ok {
				continue
			}
			txt := strings.Join(rr.Txt, "")
			if strings.Contains(strings.ToLower(txt), "v=dkim1") || strings.Contains(strings.ToLower(txt), "k=rsa") || strings.Contains(strings.ToLower(txt), "p=") {
				o.DKIMFound = append(o.DKIMFound, selector)
				o.DKIMTXT = append(o.DKIMTXT, txt)
			}
		}
	}
	sort.Strings(o.DKIMFound)
}

func dnsQuery(name string, qtype uint16, timeout time.Duration) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Timeout: timeout}
	r, _, err := c.Exchange(m, "1.1.1.1:53")
	return r, err
}

func updateTTL(o *audit.DNSObservation, ttl uint32) {
	if ttl == 0 {
		return
	}
	if o.MinTTL == 0 || ttl < o.MinTTL {
		o.MinTTL = ttl
	}
	if ttl > o.MaxTTL {
		o.MaxTTL = ttl
	}
}

func collectHTTP(ctx context.Context, domain string, opts Options) audit.HTTPObservation {
	o := audit.HTTPObservation{URL: "https://" + domain, HTTPURL: "http://" + domain}
	client := &http.Client{Timeout: opts.Timeout}
	o.HTTPStatusCode, o.RedirectedHTTPS, o.FinalURL = probeHTTPRedirect(ctx, client, o.HTTPURL, opts.UserAgent)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.URL, nil)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, br, zstd")
	var start time.Time
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() {
		o.TTFB = time.Since(start)
		o.TTFBMillis = o.TTFB.Milliseconds()
	}}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	defer resp.Body.Close()
	o.StatusCode = resp.StatusCode
	o.Headers = resp.Header
	o.Cookies = resp.Cookies()
	o.Protocol = resp.Proto
	if o.FinalURL == "" {
		o.FinalURL = resp.Request.URL.String()
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	o.Body = string(body)
	o.BodySize = len(body)
	parseHTML(&o)
	return o
}

func probeHTTPRedirect(ctx context.Context, client *http.Client, rawURL, userAgent string) (int, bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, false, ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, ""
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Request.URL.Scheme == "https", resp.Request.URL.String()
}

func parseHTML(o *audit.HTTPObservation) {
	o.Meta = map[string]string{}
	o.Links = map[string][]string{}
	o.Headings = map[string][]string{}
	doc, err := html.Parse(strings.NewReader(o.Body))
	if err != nil {
		return
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "html":
				if v := attr(n, "lang"); v != "" {
					o.Language = v
				}
			case "title":
				o.Title = strings.TrimSpace(textContent(n))
			case "meta":
				name := firstNonEmpty(attr(n, "name"), attr(n, "property"))
				if name != "" {
					o.Meta[strings.ToLower(name)] = attr(n, "content")
				}
			case "link":
				rel := strings.ToLower(attr(n, "rel"))
				if rel != "" {
					o.Links[rel] = append(o.Links[rel], attr(n, "href"))
				}
			case "h1", "h2", "h3":
				o.Headings[n.Data] = append(o.Headings[n.Data], strings.TrimSpace(textContent(n)))
			case "img":
				o.ImagesTotal++
				if strings.TrimSpace(attr(n, "alt")) == "" {
					o.ImagesMissingAlt++
				}
			case "script":
				if strings.Contains(strings.ToLower(attr(n, "type")), "ld+json") {
					o.JSONLDCount++
				}
			case "main", "nav", "header", "footer", "aside":
				o.LandmarkCount++
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func textContent(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for child := x.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func collectTLS(ctx context.Context, domain string, timeout time.Duration) audit.TLSObservation {
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return audit.TLSObservation{Error: err.Error()}
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	o := audit.TLSObservation{
		Presented:        len(state.PeerCertificates) > 0,
		Version:          tlsVersion(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		VerifiedHostname: len(state.VerifiedChains) > 0,
		ChainLength:      len(state.PeerCertificates),
		ALPN:             state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		o.Subject = cert.Subject.String()
		o.Issuer = cert.Issuer.String()
		o.NotAfter = cert.NotAfter
		o.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		o.DNSNames = cert.DNSNames
		if err := cert.VerifyHostname(domain); err == nil {
			o.VerifiedHostname = true
		}
	}
	return o
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func fetchText(ctx context.Context, rawURL string, opts Options) audit.TextFetch {
	o := audit.TextFetch{URL: rawURL}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	defer resp.Body.Close()
	o.StatusCode = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 200_000))
	o.Body = string(body)
	return o
}

func collectRDAP(ctx context.Context, domain string, opts Options) audit.RDAPObservation {
	tf := fetchText(ctx, "https://rdap.org/domain/"+url.PathEscape(domain), opts)
	if tf.Error != "" {
		return audit.RDAPObservation{Error: tf.Error}
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(tf.Body), &raw); err != nil {
		return audit.RDAPObservation{Error: err.Error()}
	}
	o := audit.RDAPObservation{Domain: fmt.Sprint(raw["ldhName"])}
	if entities, ok := raw["entities"].([]any); ok {
		for _, entity := range entities {
			if m, ok := entity.(map[string]any); ok {
				if roles, ok := m["roles"].([]any); ok && containsAnyString(roles, "registrar") {
					o.Registrar = fmt.Sprint(m["handle"])
				}
			}
		}
	}
	if events, ok := raw["events"].([]any); ok {
		for _, event := range events {
			if m, ok := event.(map[string]any); ok {
				o.Events = append(o.Events, fmt.Sprintf("%v:%v", m["eventAction"], m["eventDate"]))
			}
		}
	}
	return o
}

func containsAnyString(vals []any, needle string) bool {
	for _, v := range vals {
		if fmt.Sprint(v) == needle {
			return true
		}
	}
	return false
}

func collectCT(ctx context.Context, domain string, opts Options) audit.CTObservation {
	tf := fetchText(ctx, "https://crt.sh/?q=%25."+url.QueryEscape(domain)+"&output=json", opts)
	if tf.Error != "" {
		return audit.CTObservation{Error: tf.Error}
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(tf.Body), &rows); err != nil {
		return audit.CTObservation{Error: err.Error()}
	}
	seen := map[string]bool{}
	for _, row := range rows {
		for _, name := range strings.Split(fmt.Sprint(row["name_value"]), "\n") {
			name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
			if strings.HasSuffix(name, domain) {
				seen[name] = true
			}
		}
		if len(seen) >= 200 {
			break
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return audit.CTObservation{KnownNames: out}
}

func collectM365(ctx context.Context, domain string, dnsObs audit.DNSObservation, opts Options) audit.M365Observation {
	o := audit.M365Observation{LegacyAuthProbe: "not_tested_without_credentials"}
	for _, mx := range dnsObs.MX {
		lower := strings.ToLower(mx)
		if strings.Contains(lower, "mail.protection.outlook.com") || strings.Contains(lower, "outlook.com") {
			o.MXSignals = append(o.MXSignals, mx)
		}
	}
	for _, txt := range dnsObs.MSVerify {
		o.TXTSignals = append(o.TXTSignals, txt)
	}
	o.Autodiscover = append(o.Autodiscover, dnsObs.Autodiscover...)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.microsoftonline.com/"+url.PathEscape(domain)+"/v2.0/.well-known/openid-configuration", nil)
	if err == nil {
		req.Header.Set("User-Agent", opts.UserAgent)
		resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
		if err != nil {
			o.Error = err.Error()
		} else {
			o.OpenIDStatusCode = resp.StatusCode
			var raw map[string]any
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 200_000))
			_ = resp.Body.Close()
			if json.Unmarshal(body, &raw) == nil {
				o.OpenIDIssuer = fmt.Sprint(raw["issuer"])
			}
		}
	}
	o.Detected = len(o.MXSignals) > 0 || len(o.TXTSignals) > 0 || len(o.Autodiscover) > 0 || o.OpenIDStatusCode == 200
	return o
}

func collectReputation(ctx context.Context, domain string, opts Options) audit.ReputationObservation {
	return audit.ReputationObservation{
		SpamhausDBL: queryDomainDNSBL(domain, "dbl.spamhaus.org", opts.Timeout),
		SURBL:       queryDomainDNSBL(domain, "multi.surbl.org", opts.Timeout),
		URLHaus:     collectURLHaus(ctx, domain, opts),
		VirusTotal:  collectVirusTotal(ctx, domain, opts),
	}
}

func queryDomainDNSBL(domain string, zone string, timeout time.Duration) audit.ReputationRecord {
	record := audit.ReputationRecord{Checked: true}
	msg, err := dnsQuery(domain+"."+zone, dns.TypeA, timeout)
	if err != nil {
		record.Status = "not_listed"
		return record
	}
	for _, ans := range msg.Answer {
		if rr, ok := ans.(*dns.A); ok {
			record.Listed = true
			record.Status = "listed"
			record.Categories = append(record.Categories, rr.A.String())
		}
	}
	if !record.Listed {
		record.Status = "not_listed"
	}
	return record
}

func collectURLHaus(ctx context.Context, domain string, opts Options) audit.ReputationRecord {
	record := audit.ReputationRecord{Checked: true, URL: "https://urlhaus-api.abuse.ch/v1/host/"}
	form := url.Values{"host": {domain}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, record.URL, strings.NewReader(form.Encode()))
	if err != nil {
		record.Error = err.Error()
		return record
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
	if err != nil {
		record.Error = err.Error()
		return record
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500_000))
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		record.Error = err.Error()
		return record
	}
	status := fmt.Sprint(raw["query_status"])
	record.Status = status
	if status == "ok" {
		record.Listed = true
		record.Categories = append(record.Categories, "urlhaus_host")
	}
	return record
}

func collectVirusTotal(ctx context.Context, domain string, opts Options) audit.ReputationRecord {
	record := audit.ReputationRecord{Checked: false, URL: "https://www.virustotal.com/api/v3/domains/" + domain}
	key := strings.TrimSpace(os.Getenv("DOMAIN_SCORE_VIRUSTOTAL_API_KEY"))
	if key == "" {
		record.Status = "api_key_required"
		record.Error = "VirusTotal domain reputation requires DOMAIN_SCORE_VIRUSTOTAL_API_KEY in a local CLI."
		return record
	}
	record.Checked = true
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, record.URL, nil)
	if err != nil {
		record.Error = err.Error()
		return record
	}
	req.Header.Set("x-apikey", key)
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
	if err != nil {
		record.Error = err.Error()
		return record
	}
	defer resp.Body.Close()
	var raw map[string]any
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500_000))
	if err := json.Unmarshal(body, &raw); err != nil {
		record.Error = err.Error()
		return record
	}
	record.Status = fmt.Sprintf("http_%d", resp.StatusCode)
	if data, ok := raw["data"].(map[string]any); ok {
		if attrs, ok := data["attributes"].(map[string]any); ok {
			if stats, ok := attrs["last_analysis_stats"].(map[string]any); ok {
				if malicious, ok := stats["malicious"].(float64); ok {
					record.Score = int(malicious)
					record.Listed = malicious > 0
				}
			}
		}
	}
	return record
}

func collectExternal(ctx context.Context, domain string, dnsObs audit.DNSObservation, opts Options) audit.ExternalObservation {
	return audit.ExternalObservation{
		MozillaObservatory: collectMozillaObservatory(ctx, domain, opts),
		SSLLabs:            collectSSLLabs(ctx, domain, opts),
		Shodan:             collectInternetDB(ctx, domain, dnsObs, opts),
	}
}

func collectMozillaObservatory(ctx context.Context, domain string, opts Options) audit.ExternalGrade {
	endpoint := "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=" + url.QueryEscape(domain)
	grade := audit.ExternalGrade{Checked: true, URL: endpoint}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		grade.Error = err.Error()
		return grade
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
	if err != nil {
		grade.Error = err.Error()
		return grade
	}
	defer resp.Body.Close()
	grade.Status = fmt.Sprintf("http_%d", resp.StatusCode)
	var raw map[string]any
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500_000))
	if json.Unmarshal(body, &raw) == nil {
		grade.Grade = firstJSONText(raw, "grade", "scan_grade")
		grade.Score = int(firstJSONFloat(raw, "score"))
	}
	return grade
}

func collectSSLLabs(ctx context.Context, domain string, opts Options) audit.ExternalGrade {
	endpoint := "https://api.ssllabs.com/api/v3/analyze?publish=off&fromCache=on&all=done&host=" + url.QueryEscape(domain)
	grade := audit.ExternalGrade{Checked: true, URL: endpoint}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		grade.Error = err.Error()
		return grade
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
	if err != nil {
		grade.Error = err.Error()
		return grade
	}
	defer resp.Body.Close()
	grade.Status = fmt.Sprintf("http_%d", resp.StatusCode)
	var raw map[string]any
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1_000_000))
	if json.Unmarshal(body, &raw) == nil {
		grade.Status = fmt.Sprint(raw["status"])
		if endpoints, ok := raw["endpoints"].([]any); ok && len(endpoints) > 0 {
			if first, ok := endpoints[0].(map[string]any); ok {
				grade.Grade = fmt.Sprint(first["grade"])
			}
		}
	}
	return grade
}

func collectInternetDB(ctx context.Context, domain string, dnsObs audit.DNSObservation, opts Options) audit.ShodanResult {
	result := audit.ShodanResult{Checked: true}
	ips := append([]string{}, dnsObs.A...)
	if len(ips) == 0 {
		result.Error = "no A records to query"
		return result
	}
	seenCVEs := map[string]bool{}
	seenPorts := map[int]bool{}
	seenHosts := map[string]bool{}
	for _, ip := range ips {
		endpoint := "https://internetdb.shodan.io/" + url.PathEscape(ip)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", opts.UserAgent)
		resp, err := (&http.Client{Timeout: opts.Timeout}).Do(req)
		if err != nil {
			result.Error = err.Error()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 500_000))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
			continue
		}
		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil {
			continue
		}
		for _, port := range anySlice(raw["ports"]) {
			if p, ok := numericInt(port); ok {
				seenPorts[p] = true
			}
		}
		for _, cve := range anySlice(raw["vulns"]) {
			seenCVEs[fmt.Sprint(cve)] = true
		}
		for _, host := range anySlice(raw["hostnames"]) {
			seenHosts[fmt.Sprint(host)] = true
		}
	}
	for p := range seenPorts {
		result.Ports = append(result.Ports, p)
	}
	for cve := range seenCVEs {
		result.CVEs = append(result.CVEs, cve)
	}
	for host := range seenHosts {
		result.Hostnames = append(result.Hostnames, host)
	}
	sort.Ints(result.Ports)
	sort.Strings(result.CVEs)
	sort.Strings(result.Hostnames)
	result.Open = len(result.Ports) > 0 || len(result.CVEs) > 0
	return result
}

func anySlice(v any) []any {
	if vals, ok := v.([]any); ok {
		return vals
	}
	return nil
}

func numericInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}

func firstJSONText(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if val := fmt.Sprint(raw[key]); val != "" && val != "<nil>" {
			return val
		}
	}
	return ""
}

func firstJSONFloat(raw map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if val, ok := raw[key].(float64); ok {
			return val
		}
	}
	return 0
}

func collectAggressive(ctx context.Context, domain string, ev audit.SharedEvidence, opts Options) audit.AggressiveObservation {
	o := audit.AggressiveObservation{
		SensitivePaths: map[string]int{},
		ServiceBanners: map[string]string{},
		AXFR:           map[string]string{},
	}
	o.CrawledURLs, o.BrokenLinks, o.MixedContent = crawl(ctx, domain, opts)
	o.OpenPorts, o.ServiceBanners = scanPorts(ctx, domain)
	o.SensitivePaths = probeSensitive(ctx, domain, opts)
	o.Subdomains = enumerateSubdomains(domain, ev.CT.KnownNames, opts.Timeout)
	o.FrameworkSignals = fingerprint(ev.HTTP)
	o.ExposedTokenHints = tokenHints(ev.HTTP.Body)
	o.CVEHints = cveHints(o.ServiceBanners, o.FrameworkSignals)
	o.AXFR = probeAXFR(domain, ev.DNS.NS)
	return o
}

func crawl(ctx context.Context, domain string, opts Options) ([]string, []string, []string) {
	c := colly.NewCollector(
		colly.AllowedDomains(domain, "www."+domain),
		colly.MaxDepth(2),
		colly.Async(false),
		colly.UserAgent(opts.UserAgent),
	)
	_ = c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: 1, Delay: 400 * time.Millisecond})
	visited := []string{}
	broken := []string{}
	mixed := []string{}
	c.OnRequest(func(r *colly.Request) {
		if len(visited) < 30 {
			visited = append(visited, r.URL.String())
		}
	})
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		if len(visited) >= 30 {
			return
		}
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link != "" {
			_ = e.Request.Visit(link)
		}
	})
	c.OnHTML("img[src],script[src],link[href]", func(e *colly.HTMLElement) {
		for _, key := range []string{"src", "href"} {
			v := e.Attr(key)
			if strings.HasPrefix(v, "http://") {
				mixed = append(mixed, v)
			}
		}
	})
	c.OnResponse(func(r *colly.Response) {
		if r.StatusCode >= 400 {
			broken = append(broken, r.Request.URL.String())
		}
	})
	c.OnError(func(r *colly.Response, err error) {
		if r != nil && r.Request != nil {
			broken = append(broken, r.Request.URL.String())
		}
	})
	done := make(chan struct{})
	go func() {
		_ = c.Visit("https://" + domain)
		close(done)
	}()
	select {
	case <-ctx.Done():
	case <-time.After(15 * time.Second):
	case <-done:
	}
	return unique(visited), unique(broken), unique(mixed)
}

func scanPorts(ctx context.Context, domain string) ([]int, map[string]string) {
	ports := []int{21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443}
	open := []int{}
	banners := map[string]string{}
	for _, port := range ports {
		d := net.Dialer{Timeout: 900 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(domain, fmt.Sprint(port)))
		if err != nil {
			continue
		}
		open = append(open, port)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 128)
		if n, err := conn.Read(buf); err == nil && n > 0 {
			banners[fmt.Sprint(port)] = strings.TrimSpace(string(buf[:n]))
		}
		_ = conn.Close()
	}
	return open, banners
}

func probeSensitive(ctx context.Context, domain string, opts Options) map[string]int {
	paths := []string{"/.env", "/.git/config", "/backup.zip", "/db.sql", "/config.php.bak", "/wp-config.php~", "/admin", "/server-status", "/sitemap.xml.gz.map", "/app.js.map"}
	found := map[string]int{}
	client := &http.Client{Timeout: opts.Timeout}
	for _, p := range paths {
		rawURL := "https://" + domain + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", opts.UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			found[p] = resp.StatusCode
		}
	}
	return found
}

func enumerateSubdomains(domain string, ctNames []string, timeout time.Duration) []string {
	seen := map[string]bool{}
	for _, n := range ctNames {
		if n != domain {
			seen[n] = true
		}
	}
	for _, prefix := range []string{"www", "mail", "api", "dev", "staging", "admin", "app", "cdn"} {
		name := prefix + "." + domain
		if msg, err := dnsQuery(name, dns.TypeA, timeout); err == nil && msg != nil && len(msg.Answer) > 0 {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func fingerprint(http audit.HTTPObservation) []string {
	signals := []string{}
	body := strings.ToLower(http.Body)
	for _, sig := range []string{"wp-content", "drupal", "joomla", "next.js", "__nuxt", "laravel", "django"} {
		if strings.Contains(body, sig) {
			signals = append(signals, sig)
		}
	}
	for _, h := range []string{"Server", "X-Powered-By"} {
		if v := http.Headers[h]; len(v) > 0 && v[0] != "" {
			signals = append(signals, h+": "+v[0])
		}
	}
	return unique(signals)
}

func tokenHints(body string) []string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)api[_-]?key["'\s:=]+[a-z0-9_\-]{16,}`),
		regexp.MustCompile(`(?i)secret["'\s:=]+[a-z0-9_\-]{16,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	}
	hints := []string{}
	for _, re := range patterns {
		for _, m := range re.FindAllString(body, 5) {
			if len(m) > 80 {
				m = m[:80]
			}
			hints = append(hints, m)
		}
	}
	return unique(hints)
}

func cveHints(banners map[string]string, frameworkSignals []string) []string {
	haystack := strings.ToLower(strings.Join(frameworkSignals, "\n"))
	for port, banner := range banners {
		haystack += "\n" + port + ":" + strings.ToLower(banner)
	}
	hints := []string{}
	signatures := map[string]string{
		"apache/2.4.49": "Apache httpd 2.4.49 path traversal/RCE family (CVE-2021-41773)",
		"apache/2.4.50": "Apache httpd 2.4.50 path traversal/RCE family (CVE-2021-42013)",
		"apache/2.4.51": "Apache httpd 2.4.51 historically shown by scanners as outdated; verify patch level",
		"openssh_7.":    "OpenSSH 7.x is old; verify vendor backports and CVEs",
		"openssh 7.":    "OpenSSH 7.x is old; verify vendor backports and CVEs",
		"php/5.":        "PHP 5.x is end-of-life",
		"php/7.":        "PHP 7.x is end-of-life",
		"wordpress":     "WordPress detected; verify core, plugin and theme CVEs",
		"drupal":        "Drupal detected; verify core/module CVEs",
		"joomla":        "Joomla detected; verify extension CVEs",
	}
	for needle, hint := range signatures {
		if strings.Contains(haystack, needle) {
			hints = append(hints, hint)
		}
	}
	return unique(hints)
}

func probeAXFR(domain string, nameservers []string) map[string]string {
	out := map[string]string{}
	for _, ns := range nameservers {
		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))
		ch, err := t.In(m, net.JoinHostPort(ns, "53"))
		if err != nil {
			out[ns] = "blocked"
			continue
		}
		allowed := false
		for env := range ch {
			if env.Error == nil && len(env.RR) > 0 {
				allowed = true
				break
			}
		}
		if allowed {
			out[ns] = "allowed"
		} else {
			out[ns] = "blocked"
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
