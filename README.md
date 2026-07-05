# Domain Score

Domain Score is a Go CLI for auditing publicly visible domain signals across security, DNS, TLS, HTTP headers, SEO, AI-readiness, performance and transparency.

The default scan is intentionally non-invasive. Aggressive checks such as limited crawling, port probing, sensitive path checks and DNS AXFR attempts only run when explicitly enabled.

## Install

Download a binary from GitHub Releases, or build locally:

```sh
go install github.com/kolisko/domain-score/cmd/domain-score@latest
```

## Usage

```sh
domain-score scan example.com
domain-score scan example.com --format json,md --out ./reports
domain-score scan https://example.com --out - --format json
domain-score scan example.com --details findings
domain-score scan example.com --details-check dns.dmarc
domain-score scan example.com --check dns.dmarc
domain-score scan example.com --check network.open_ports
domain-score scan example.com --tools all
domain-score tools doctor
domain-score tools pull
domain-score scan example.com --aggressive
domain-score list-checks
domain-score list internal-checks
domain-score explain dns.dnssec_enabled
domain-score update
```

By default, `scan` prints a colorized aligned console table to stdout, one row
per check, sorted by check weight descending. Use `--no-color` to disable ANSI
colors.

The required argument after `scan` is the domain to audit. Pass a bare domain
such as `example.com`, or a URL such as `https://example.com`; Domain Score
extracts the hostname and audits that public domain.

Useful flags:

- `--profile safe|standard|aggressive`: choose the scan profile. Default is `safe`.
- `--aggressive`: enable all aggressive checks and their collectors.
- `--enable check.id`: enable one or more checks explicitly.
- `--disable check.id`: disable one or more checks.
- `--weights weights.yml`: override scoring weights.
- `--format console,json,md`: choose output formats. Default is `console`.
- `--sort weight|status|category|id|none`: sort console and Markdown check rows. Default is `weight`.
- `--details off|findings|all`: add detailed explanations to console and Markdown reports. Default is `off`.
- `--details-check check.id`: add a detailed explanation for one concrete check.
- `--check check.id`: run one internal or catalog atomic check. Catalog checks use their mapped internal check or external Docker tool when available.
- `--tools none|all|subfinder,httpx,naabu,nuclei,amass,testssl,zap,internetnl,greenbone`: run Docker-based external tools. Default is `none`.
- `--tools-pull auto|always|never`: control external tools image pulls. Default is `auto`.
- `--tools-timeout 60m`: timeout for external Docker tools.
- `--out -`: print selected report formats to stdout.

`list-checks` and `list internal-checks` show executable built-in Go checks.
The broader product catalog of atomic checks lives in
`catalog/atomic-checks.yaml`; it is the development specification for desired
checks, coverage mappings and future external tool normalization. The bounded
v1 catalog audit is documented in `docs/catalog-v1-audit.md`, and source
research evidence is tracked in `catalog/source-research-evidence.yaml`.

An atomic check is a type of audited condition, not a concrete finding. For
example, `network.open_ports` is one check that can produce many findings such
as port 22 and 443. Runtime values belong to findings, while tools such as
naabu, ZAP, Nuclei, testssl or Greenbone are evidence sources.

Public third-party checks that do not need user API keys run in the default
safe profile when available: Spamhaus DBL, SURBL, URLhaus host reputation,
Shodan InternetDB, SSL Labs cached grade, Mozilla Observatory, Certificate
Transparency and Microsoft 365 public tenant discovery. Checks that require a
provider account, such as VirusTotal's domain API, report `not_applicable`
unless the relevant environment variable is configured.

Example weights file:

```yaml
weights:
  dns.dnssec_enabled: 5
  http.csp: 7
```

## Updates

Release binaries can update themselves:

```sh
domain-score update
```

The update command downloads the matching GitHub Release archive for your
OS/architecture, shows download progress, verifies the GitHub asset sha256
digest when available, extracts the `domain-score` binary, replaces the current
executable, and cleans up temporary files.

Release builds check the latest GitHub Release before running `scan`. If a newer
release exists, the scan stops and asks you to run `domain-score update` first.
Development builds with version `dev` skip this check.

## Safety Model

Safe checks are default and use normal public discovery: DNS queries, HTTP(S) requests, TLS handshakes, RDAP and Certificate Transparency lookups.

Safe checks may also query public third-party reputation or grading sources that
do not attack the target and do not require credentials from the user.

Aggressive checks are opt-in and remain non-exploitative:

- rate-limited crawl with a small URL cap
- limited top-port probing
- common sensitive path checks without authentication or exploitation
- subdomain discovery from CT and a small wordlist
- DNS AXFR attempt against nameservers
- static token-like hints from public HTML

Domain Score does not perform brute force, denial of service, authenticated scanning, exploit delivery or state-changing actions.

## Docker Tools

External tools run in one Docker image so the host system does not need separate
tool installations:

```sh
domain-score scan example.com --tools all
domain-score scan example.com --tools projectdiscovery
domain-score scan example.com --tools subfinder,httpx,nuclei
domain-score tools doctor
domain-score tools pull
domain-score tools list
```

The default image is an embedded, pinned GHCR digest. The current logical tools
release is `ghcr.io/kolisko/domain-score-tools:tools-v0.1.4`, and the CLI uses
the exact digest for that image by default instead of `latest` or the CLI
version tag. If the image is missing and `--tools-pull auto` is used, Domain
Score pulls it automatically. Docker Desktop or Docker Engine must already be
installed and running; Domain Score does not install Docker itself.

CLI releases and tools image releases are intentionally separate. A normal
`v*` CLI release does not rebuild the tools image. The tools image is published
only from the dedicated `tools-v*` image workflow or a manual image workflow
run, which keeps CLI-only fixes fast and avoids changing scanner dependencies
without intent.

Supported tool aliases:

- `all`: subfinder, httpx, naabu, nuclei, amass, testssl, zap, internetnl, greenbone.
- `projectdiscovery`: subfinder, httpx, naabu, nuclei.
- `web-passive`: httpx, zap.
- `tls`: testssl.
- `standards`: internetnl.
- `vuln`: nuclei, greenbone.

Raw tool outputs are cached under the user cache directory at
`domain-score/tools/<domain>/latest/raw/`; each new scan replaces the previous
`latest` cache for that domain. Active tools such as port scanning, Nuclei and
Greenbone should only be used on domains and infrastructure you own or are
authorized to test.

The global `--tools-timeout` limits the whole Docker run. While tools run, their
stdout and stderr are streamed to the console and also saved in `raw/`. Nuclei
prints periodic stats during long template runs so the scan does not look stuck.

## Competitive Coverage

Domain Score covers the public audit areas commonly advertised by hosted IT and
security audit tools:

- DNS and mail security: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, IPv6, wildcard DNS.
- TLS and web security: certificate validity, expiry, hostname, chain, protocol, ALPN, SSL Labs cached grade, HSTS, CSP, X-Frame/frame-ancestors and related headers.
- Public exposure and CVE signals: Shodan InternetDB no-key service/CVE data, optional active port probing in aggressive mode, banner/framework CVE hints.
- Reputation: Spamhaus DBL, SURBL, URLhaus, and optional VirusTotal with `DOMAIN_SCORE_VIRUSTOTAL_API_KEY`.
- Microsoft 365: public tenant discovery via MX/TXT/autodiscover/OpenID signals and a clear legacy-auth verification note.
- Certificate Transparency subdomains and shadow-IT inventory signals.
- SEO, performance, accessibility and AI-readiness checks that are usually outside pure security scanners.
- Optional Docker-based external tooling: subfinder, httpx, naabu, nuclei, Amass, testssl.sh, ZAP Baseline, Internet.nl and Greenbone wrappers.

## Check API

Each check implements:

```go
type Check interface {
    Meta() CheckMeta
    Run(context.Context, Target, SharedEvidence) Result
}
```

Add a new atomic check by creating a file under `internal/checks`, returning metadata with a stable `category.id`, and registering it in `internal/checks/registry.go`.

Result statuses:

- `pass`: the property is present and acceptable.
- `warn`: improvement recommended.
- `fail`: significant missing or risky property.
- `error`: audit could not evaluate the check.
- `not_applicable`: check does not apply to this target.

## Output

`console` is the default colorized stdout format. Add `--details findings` to
explain only `fail`, `warn` and `error` checks, `--details all` to explain every
check, or `--details-check dns.dmarc` to expand one specific check. Detailed
sections include what is wrong, why it matters, evidence, how to fix it and the
recommended target state.

`report.json` is the stable automation format. `report.md` is optimized for
humans and includes the overall grade, category scores, top findings, a status
matrix table with one row per check, optional detailed explanations and detailed
check sections.

## Development

```sh
go test ./...
go run ./cmd/domain-score list-checks
go run ./cmd/domain-score list internal-checks
go run ./cmd/domain-score scan example.com --out -
```

CI runs tests, `go vet`, govulncheck and CodeQL. Releases are produced by GoReleaser for Linux, macOS and Windows on amd64 and arm64.
