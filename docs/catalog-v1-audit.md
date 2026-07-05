# Catalog v1 Audit

This document closes the first bounded catalog pass for Domain Score atomic
checks. It is a product and engineering audit of the catalog snapshot, not a
claim that every possible future rule from every security feed has been modeled
forever.

## Decision

Catalog v1 is accepted as a bounded development specification snapshot when all
inspected source catalogs are either mapped to canonical atomic checks or
explicitly classified by access/cost policy.

For v1, broad expansion stops here. Future work should promote high-value
source-specific rules into first-class canonical checks only when that improves
scoring, remediation text, or runtime reporting.

## Objective Breakdown

The requested catalog work decomposes into these verifiable parts:

- inspect available open-source/free domain, web, TLS, OSINT and vulnerability
  tools;
- identify audited conditions as atomic checks rather than per-finding runtime
  values;
- store the canonical definitions in YAML;
- store generated source-specific rule catalogs separately;
- map source rules to canonical checks;
- separate open-source/free/no-key/optional-key sources from paid or
  credentials-required sources.

## Evidence

Current validated catalog state:

- canonical atomic checks: `299`
- generated source catalogs: `21`
- generated source items: `629357`
- curated source-to-canonical mapping rules: `558`
- access/cost policies: `19`
- source research evidence entries: `19`
- unmapped source items in current coverage report: `0`

Primary files:

- `catalog/atomic-checks.yaml`
- `catalog/generated/source-catalog-manifest.yaml`
- `catalog/source-to-canonical-map.yaml`
- `catalog/generated/source-mapping-coverage.yaml`
- `catalog/source-access-policy.yaml`
- `catalog/source-research-evidence.yaml`
- `docs/tool-research-log.md`

Validation command:

```sh
ruby scripts/validate-catalog.rb
```

Expected result:

```text
catalog validation ok
```

## Sources Inspected

The v1 snapshot includes these source families and generated catalog counts:

| Source family | Source items |
| --- | ---: |
| Greenbone SCAP CVE | 363055 |
| Greenbone NVT | 95080 |
| Greenbone Notus | 86723 |
| Greenbone CERT | 70401 |
| Nuclei templates | 13375 |
| Greenbone GVMD data objects | 23 |
| Greenbone feed capabilities | 9 |
| ZAP rules | 104 |
| testssl JSON ids | 107 |
| Internet.nl subtests | 76 |
| ProjectDiscovery capabilities | 43 |
| Amass capabilities | 17 |
| Subfinder providers | 50 |
| Amass providers | 97 |
| Mozilla Observatory expectations | 66 |
| SSL Labs API fields | 64 |
| Shodan InternetDB fields | 6 |
| URLhaus host fields | 16 |
| Spamhaus DBL return codes | 13 |
| SURBL return codes | 7 |
| VirusTotal domain fields | 25 |

## Fallback Policy

Fallback mappings exist to prevent data loss when upstream tools add new rules
or when a generated source rule is too specific to deserve a canonical check in
v1.

The important broad fallback buckets are not currently hiding the main imported
rule sets:

| Canonical fallback check | Current mapped source items |
| --- | ---: |
| `web.zap_passive_or_active_alert` | 0 |
| `tls.testssl_signal_requires_review` | 0 |
| `vulnerability.nuclei_template_match` | 0 |
| `vulnerability.greenbone_nvt_match` | 0 |
| `vulnerability.notus_package_vulnerability` | 0 |

If a future feed/template update starts using these buckets, the coverage file
will show it and the affected rules can be reviewed.

## Access And Cost Boundary

Included in the free/open-source or no-key v1 scope:

- local open-source tools: Nuclei, nuclei-templates, Subfinder, Naabu, Amass,
  ZAP, testssl.sh, Internet.nl source stack, Greenbone Community Feed;
- public no-key sources: Shodan InternetDB, Spamhaus DBL, SURBL, URLhaus,
  Mozilla Observatory;
- free/optional-key sources: SSL Labs public API/cache and VirusTotal domain
  API metadata.

Out of free/default scope:

- Greenbone Enterprise Feed;
- paid Shodan API features;
- provider-specific Subfinder/Amass sources that require paid accounts;
- templates or checks that require target ownership credentials, cloud tokens,
  authenticated contexts, or customer-specific data.

Those sources may be represented in access policy metadata, but they must not
be required for the free/open-source audit path.

## Known Runtime Gaps

This catalog is a product/business specification. It intentionally leads the
runtime implementation. Not every canonical check has a parser, scorer and
reporting path yet.

Known runtime issues at this snapshot:

- the current tools image can resolve `httpx` to the Python HTTPX CLI wrapper
  instead of ProjectDiscovery httpx, so runtime evidence for that tool is not
  reliable until the image is fixed;
- Internet.nl full local execution is a multi-service stack, so current support
  is partial;
- Greenbone Community Edition requires feed sync and a full scanner stack for
  complete runtime execution; feed catalogs are indexed from synced Community
  Feed data, but full one-shot scanning is still partial.

## Backlog

Recommended next work should be finite and implementation-oriented:

- fix the tools image so ProjectDiscovery `httpx` is the command being run;
- make runtime tool parsers emit both `atomic_check_id` and source rule id;
- promote only high-value Nuclei template ids, Greenbone OIDs, ZAP plugin ids
  or CVEs into canonical checks when they need unique scoring/remediation;
- add report views that can show canonical check coverage, source evidence and
  concrete findings separately;
- regenerate source catalogs after upstream feed/template updates and review
  new fallback usage.

## Completion Assessment

For the bounded v1 objective, the catalog pass is complete: the inspected
open-source/free/no-key/optional-key sources are cataloged, classified and
covered by normalization rules.

The literal objective "all possible checks from all possible tools" cannot be
proven as a final state. Domain Score should treat the generated manifest and
this audit document as the boundary of the v1 snapshot.
