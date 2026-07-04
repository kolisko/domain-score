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
	return o
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
