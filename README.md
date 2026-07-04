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
domain-score scan example.com --format json,md --out ./reports
domain-score scan example.com --aggressive --out ./reports/aggressive
domain-score list-checks
domain-score explain dns.dnssec_enabled
```

Useful flags:

- `--profile safe|standard|aggressive`: choose the scan profile. Default is `safe`.
- `--aggressive`: enable all aggressive checks and their collectors.
- `--enable check.id`: enable one or more checks explicitly.
- `--disable check.id`: disable one or more checks.
- `--weights weights.yml`: override scoring weights.
- `--out -`: print selected report formats to stdout.

Example weights file:

```yaml
weights:
  dns.dnssec_enabled: 5
  http.csp: 7
```

## Safety Model

Safe checks are default and use normal public discovery: DNS queries, HTTP(S) requests, TLS handshakes, RDAP and Certificate Transparency lookups.

Aggressive checks are opt-in and remain non-exploitative:

- rate-limited crawl with a small URL cap
- limited top-port probing
- common sensitive path checks without authentication or exploitation
- subdomain discovery from CT and a small wordlist
- DNS AXFR attempt against nameservers
- static token-like hints from public HTML

Domain Score does not perform brute force, denial of service, authenticated scanning, exploit delivery or state-changing actions.

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

`report.json` is the stable automation format. `report.md` is optimized for humans and includes the overall grade, category scores, top findings and all check results.

## Development

```sh
go test ./...
go run ./cmd/domain-score list-checks
go run ./cmd/domain-score scan example.com --out -
```

CI runs tests, `go vet`, govulncheck and CodeQL. Releases are produced by GoReleaser for Linux, macOS and Windows on amd64 and arm64.
