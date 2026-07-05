package audit

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type Mode string

const (
	ModeSafe       Mode = "safe"
	ModeAggressive Mode = "aggressive"
)

type Status string

const (
	StatusPass          Status = "pass"
	StatusWarn          Status = "warn"
	StatusFail          Status = "fail"
	StatusError         Status = "error"
	StatusNotApplicable Status = "not_applicable"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Target struct {
	Domain string   `json:"domain"`
	URLs   []string `json:"urls"`
}

type CheckMeta struct {
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Category       string        `json:"category"`
	Mode           Mode          `json:"mode"`
	Weight         int           `json:"weight"`
	Severity       Severity      `json:"severity"`
	Tags           []string      `json:"tags,omitempty"`
	Docs           string        `json:"docs,omitempty"`
	Timeout        time.Duration `json:"-"`
	DefaultTimeout string        `json:"timeout,omitempty"`
}

type Result struct {
	CheckID        string         `json:"check_id"`
	Title          string         `json:"title"`
	Category       string         `json:"category"`
	Mode           Mode           `json:"mode"`
	Status         Status         `json:"status"`
	Severity       Severity       `json:"severity"`
	Weight         int            `json:"weight"`
	ScoreImpact    int            `json:"score_impact"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
	Error          string         `json:"error,omitempty"`
	Duration       string         `json:"duration,omitempty"`
}

type Check interface {
	Meta() CheckMeta
	Run(context.Context, Target, SharedEvidence) Result
}

type SharedEvidence struct {
	DNS          DNSObservation        `json:"dns"`
	HTTP         HTTPObservation       `json:"http"`
	TLS          TLSObservation        `json:"tls"`
	Robots       TextFetch             `json:"robots"`
	Sitemap      TextFetch             `json:"sitemap"`
	LLMs         TextFetch             `json:"llms"`
	SecurityText TextFetch             `json:"security_txt"`
	RDAP         RDAPObservation       `json:"rdap"`
	CT           CTObservation         `json:"certificate_transparency"`
	M365         M365Observation       `json:"microsoft_365,omitempty"`
	Reputation   ReputationObservation `json:"reputation,omitempty"`
	External     ExternalObservation   `json:"external,omitempty"`
	Aggressive   AggressiveObservation `json:"aggressive,omitempty"`
	Tools        ToolObservation       `json:"tools,omitempty"`
	Errors       map[string]string     `json:"errors,omitempty"`
}

type DNSObservation struct {
	A            []string `json:"a,omitempty"`
	AAAA         []string `json:"aaaa,omitempty"`
	NS           []string `json:"ns,omitempty"`
	MX           []string `json:"mx,omitempty"`
	TXT          []string `json:"txt,omitempty"`
	CAA          []string `json:"caa,omitempty"`
	SOA          []string `json:"soa,omitempty"`
	DMARCTXT     []string `json:"dmarc_txt,omitempty"`
	MTASTSTXT    []string `json:"mta_sts_txt,omitempty"`
	TLSRPTTXT    []string `json:"tls_rpt_txt,omitempty"`
	BIMITXT      []string `json:"bimi_txt,omitempty"`
	DKIMTXT      []string `json:"dkim_txt,omitempty"`
	DKIMFound    []string `json:"dkim_found,omitempty"`
	MSVerify     []string `json:"ms_verify,omitempty"`
	Autodiscover []string `json:"autodiscover,omitempty"`
	DNSKEY       []string `json:"dnskey,omitempty"`
	DS           []string `json:"ds,omitempty"`
	WildcardA    []string `json:"wildcard_a,omitempty"`
	WWWAddress   []string `json:"www_address,omitempty"`
	MinTTL       uint32   `json:"min_ttl,omitempty"`
	MaxTTL       uint32   `json:"max_ttl,omitempty"`
}

type HTTPObservation struct {
	URL              string              `json:"url,omitempty"`
	HTTPURL          string              `json:"http_url,omitempty"`
	StatusCode       int                 `json:"status_code,omitempty"`
	HTTPStatusCode   int                 `json:"http_status_code,omitempty"`
	RedirectedHTTPS  bool                `json:"redirected_https"`
	FinalURL         string              `json:"final_url,omitempty"`
	Headers          map[string][]string `json:"headers,omitempty"`
	Cookies          []*http.Cookie      `json:"cookies,omitempty"`
	Body             string              `json:"-"`
	BodySize         int                 `json:"body_size,omitempty"`
	TTFB             time.Duration       `json:"-"`
	TTFBMillis       int64               `json:"ttfb_ms,omitempty"`
	Title            string              `json:"title,omitempty"`
	Meta             map[string]string   `json:"meta,omitempty"`
	Links            map[string][]string `json:"links,omitempty"`
	Headings         map[string][]string `json:"headings,omitempty"`
	ImagesTotal      int                 `json:"images_total,omitempty"`
	ImagesMissingAlt int                 `json:"images_missing_alt,omitempty"`
	JSONLDCount      int                 `json:"json_ld_count,omitempty"`
	LandmarkCount    int                 `json:"landmark_count,omitempty"`
	Protocol         string              `json:"protocol,omitempty"`
	Language         string              `json:"language,omitempty"`
	Error            string              `json:"error,omitempty"`
}

type TLSObservation struct {
	Presented        bool      `json:"presented"`
	Version          string    `json:"version,omitempty"`
	CipherSuite      string    `json:"cipher_suite,omitempty"`
	Subject          string    `json:"subject,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	NotAfter         time.Time `json:"not_after,omitempty"`
	DaysUntilExpiry  int       `json:"days_until_expiry,omitempty"`
	DNSNames         []string  `json:"dns_names,omitempty"`
	VerifiedHostname bool      `json:"verified_hostname"`
	ChainLength      int       `json:"chain_length,omitempty"`
	ALPN             string    `json:"alpn,omitempty"`
	Error            string    `json:"error,omitempty"`
}

type TextFetch struct {
	URL        string `json:"url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Body       string `json:"body,omitempty"`
	Error      string `json:"error,omitempty"`
}

type RDAPObservation struct {
	Domain    string   `json:"domain,omitempty"`
	Registrar string   `json:"registrar,omitempty"`
	Events    []string `json:"events,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type CTObservation struct {
	KnownNames []string `json:"known_names,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type M365Observation struct {
	Detected         bool     `json:"detected"`
	MXSignals        []string `json:"mx_signals,omitempty"`
	TXTSignals       []string `json:"txt_signals,omitempty"`
	Autodiscover     []string `json:"autodiscover,omitempty"`
	OpenIDIssuer     string   `json:"openid_issuer,omitempty"`
	OpenIDStatusCode int      `json:"openid_status_code,omitempty"`
	LegacyAuthProbe  string   `json:"legacy_auth_probe,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type ReputationObservation struct {
	SpamhausDBL ReputationRecord `json:"spamhaus_dbl,omitempty"`
	SURBL       ReputationRecord `json:"surbl,omitempty"`
	URLHaus     ReputationRecord `json:"urlhaus,omitempty"`
	VirusTotal  ReputationRecord `json:"virustotal,omitempty"`
}

type ReputationRecord struct {
	Checked    bool     `json:"checked"`
	Listed     bool     `json:"listed"`
	Status     string   `json:"status,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Score      int      `json:"score,omitempty"`
	URL        string   `json:"url,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type ExternalObservation struct {
	MozillaObservatory ExternalGrade `json:"mozilla_observatory,omitempty"`
	SSLLabs            ExternalGrade `json:"ssl_labs,omitempty"`
	Shodan             ShodanResult  `json:"shodan,omitempty"`
}

type ExternalGrade struct {
	Checked bool   `json:"checked"`
	Grade   string `json:"grade,omitempty"`
	Score   int    `json:"score,omitempty"`
	Status  string `json:"status,omitempty"`
	URL     string `json:"url,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ShodanResult struct {
	Checked   bool     `json:"checked"`
	Open      bool     `json:"open"`
	Ports     []int    `json:"ports,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type AggressiveObservation struct {
	CrawledURLs       []string          `json:"crawled_urls,omitempty"`
	BrokenLinks       []string          `json:"broken_links,omitempty"`
	MixedContent      []string          `json:"mixed_content,omitempty"`
	OpenPorts         []int             `json:"open_ports,omitempty"`
	SensitivePaths    map[string]int    `json:"sensitive_paths,omitempty"`
	Subdomains        []string          `json:"subdomains,omitempty"`
	ServiceBanners    map[string]string `json:"service_banners,omitempty"`
	FrameworkSignals  []string          `json:"framework_signals,omitempty"`
	ExposedTokenHints []string          `json:"exposed_token_hints,omitempty"`
	CVEHints          []string          `json:"cve_hints,omitempty"`
	AXFR              map[string]string `json:"axfr,omitempty"`
}

type ToolObservation struct {
	Enabled     bool          `json:"enabled"`
	Runtime     string        `json:"runtime,omitempty"`
	Image       string        `json:"image,omitempty"`
	CacheDir    string        `json:"cache_dir,omitempty"`
	Selected    []string      `json:"selected,omitempty"`
	Findings    []ToolFinding `json:"findings,omitempty"`
	Statuses    []ToolStatus  `json:"statuses,omitempty"`
	Errors      []string      `json:"errors,omitempty"`
	RawFiles    []string      `json:"raw_files,omitempty"`
	Duration    string        `json:"duration,omitempty"`
	PullPolicy  string        `json:"pull_policy,omitempty"`
	ImagePulled bool          `json:"image_pulled,omitempty"`
}

type ToolStatus struct {
	Tool           string `json:"tool"`
	Status         string `json:"status,omitempty"`
	ExitCode       int    `json:"exit_code,omitempty"`
	ElapsedSeconds int    `json:"elapsed_seconds,omitempty"`
}

type ToolFinding struct {
	Source            string         `json:"source"`
	Tool              string         `json:"tool"`
	Asset             string         `json:"asset,omitempty"`
	Type              string         `json:"type,omitempty"`
	Severity          string         `json:"severity,omitempty"`
	Title             string         `json:"title"`
	AtomicCheckID     string         `json:"atomic_check_id,omitempty"`
	SourceRuleID      string         `json:"source_rule_id,omitempty"`
	SourceRuleGroup   string         `json:"source_rule_group,omitempty"`
	MappingConfidence string         `json:"mapping_confidence,omitempty"`
	Evidence          map[string]any `json:"evidence,omitempty"`
	Recommendation    string         `json:"recommendation,omitempty"`
	RawFile           string         `json:"raw_file,omitempty"`
}

type Report struct {
	Target      Target         `json:"target"`
	GeneratedAt time.Time      `json:"generated_at"`
	Profile     string         `json:"profile"`
	Aggressive  bool           `json:"aggressive"`
	Score       ScoreSummary   `json:"score"`
	Results     []Result       `json:"results"`
	Evidence    SharedEvidence `json:"evidence"`
	Version     string         `json:"version"`
}

type ScoreSummary struct {
	Overall    int                      `json:"overall"`
	Grade      string                   `json:"grade"`
	Categories map[string]CategoryScore `json:"categories"`
}

type CategoryScore struct {
	Score        int `json:"score"`
	PassedWeight int `json:"passed_weight"`
	TotalWeight  int `json:"total_weight"`
	Checks       int `json:"checks"`
}

func ParseTarget(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, err
	}
	if u.Scheme == "" {
		u, err = url.Parse("https://" + raw)
		if err != nil {
			return Target{}, err
		}
	}
	host := u.Hostname()
	if host == "" {
		host = raw
	}
	return Target{
		Domain: host,
		URLs: []string{
			"https://" + host,
			"http://" + host,
		},
	}, nil
}
