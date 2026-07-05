# Atomic Check Catalog

The atomic check catalog is the product specification for what Domain Score
should be able to audit. It is intentionally different from `domain-score
list-checks`.

- `list-checks` shows implemented internal Go checks.
- `catalog/atomic-checks.yaml` is the business and product catalog of desired
  atomic checks, including checks that are implemented, partially covered by
  external tools, or only planned.
- `catalog/generated/*.yaml` contains generated source-specific rule catalogs
  for large open-source tools.
- Scan findings are runtime data and should reference an atomic check id.

## Core Terms

An **atomic check** is a type of property, weakness, exposure, compliance
requirement or vulnerability condition.

A **finding** is a concrete occurrence of an atomic check on a concrete asset.
One atomic check can produce many findings.

A **tool** is an evidence source. One tool can provide evidence for many atomic
checks, and multiple tools can support the same atomic check.

## Identity Rule

Do not create atomic checks for runtime values.

Good:

```text
network.open_ports
service.version_disclosure
http.csp_missing_or_weak
vulnerability.known_cve_detected
```

Bad:

```text
network.open_port.22
network.open_port.443
service.version_disclosure.nginx.1.18.0
```

Ports, URLs, hosts, IPs, banners and concrete values belong to findings:

```yaml
atomic_check_id: network.open_ports
findings:
  - host: example.com
    port: 22
  - host: example.com
    port: 443
```

Stable external rule identifiers can become atomic checks when they represent a
distinct condition, for example a ZAP plugin id, Nuclei template id, Greenbone
NVT OID or CVE id.

## Source Of Truth

The initial product catalog lives in:

```text
catalog/atomic-checks.yaml
```

Generated source-specific catalogs live in:

```text
catalog/generated/source-catalog-manifest.yaml
catalog/generated/nuclei-template-index.yaml
catalog/generated/testssl-jsonid-index.yaml
catalog/generated/zap-rule-index.yaml
catalog/generated/internetnl-subtest-index.yaml
catalog/generated/greenbone-feed-capability-index.yaml
catalog/generated/greenbone-nvt-index.yaml.gz
catalog/generated/greenbone-notus-advisory-index.yaml.gz
catalog/generated/greenbone-cert-advisory-index.yaml.gz
catalog/generated/greenbone-gvmd-data-object-index.yaml
catalog/generated/greenbone-scap-cve-index.yaml.gz
catalog/generated/projectdiscovery-capability-index.yaml
catalog/generated/amass-capability-index.yaml
catalog/generated/subfinder-provider-index.yaml
catalog/generated/amass-provider-index.yaml
catalog/generated/mozilla-observatory-expectation-index.yaml
catalog/generated/ssl-labs-api-field-index.yaml
catalog/generated/shodan-internetdb-field-index.yaml
catalog/generated/urlhaus-host-field-index.yaml
catalog/generated/spamhaus-dbl-return-code-index.yaml
catalog/generated/surbl-return-code-index.yaml
catalog/generated/virustotal-domain-field-index.yaml
```

The curated normalization map lives in:

```text
catalog/source-to-canonical-map.yaml
catalog/generated/source-mapping-coverage.yaml
catalog/source-access-policy.yaml
catalog/source-research-evidence.yaml
```

These files are intentionally separate from the canonical `checks:` list:

- canonical checks describe audited concepts Domain Score scores and explains;
- generated source checks describe stable rule IDs exposed by tools;
- a generated rule may map to an existing canonical check, or it may later
  justify creating a new canonical check;
- the normalization map records known source-to-canonical mappings used by
  parsers and report normalization;
- the research evidence file records official repositories, docs, public APIs
  or feeds used to derive the source catalogs;
- runtime findings should keep both the canonical check id and the source rule
  id when both are known.

Research evidence and the exact source/tool families inspected are recorded in:

```text
docs/tool-research-log.md
docs/catalog-v1-audit.md
```

Each entry should define:

- stable `id`
- title and description
- category, mode, severity and weight
- implementation coverage status
- internal check ids or external tools that can provide evidence
- finding cardinality and expected evidence model
- rationale and remediation

## Development Flow

1. Add or refine an entry in `catalog/atomic-checks.yaml`.
2. Map existing internal checks or external tool rules under `implemented_by`.
3. Implement parser/normalization so runtime findings include
   `atomic_check_id`.
4. Add scoring and report behavior only after the check definition is clear.

This keeps the project centered on the audited condition rather than on the
tool that happened to detect it.

## Regenerating Source Catalogs

Run the generator inside the tools image:

```sh
docker run --rm -v "$PWD:/work" --entrypoint python3 \
  ghcr.io/kolisko/domain-score-tools:v0.6.5 \
  /work/scripts/generate-source-catalogs.py
```

To include Greenbone Community NVT, Notus, CERT, GVMD data objects and SCAP CVE
OIDs, sync the free feed data into a local cache outside the repository and pass
those directories to the generator:

```sh
docker run --rm \
  -v "$PWD:/work" \
  -v /private/tmp/domain-score-greenbone-feed:/greenbone-feed \
  --entrypoint sh domain-score-tools:rsync-test \
  -lc 'greenbone-feed-sync --type nasl --destination-prefix /greenbone-feed --no-permission-change --user root --group root --fail-fast --quiet && greenbone-feed-sync --type notus --destination-prefix /greenbone-feed --no-permission-change --user root --group root --fail-fast --quiet && greenbone-feed-sync --type cert --destination-prefix /greenbone-feed --no-permission-change --user root --group root --fail-fast --quiet && greenbone-feed-sync --type gvmd-data --destination-prefix /greenbone-feed --no-permission-change --user root --group root --fail-fast --quiet && greenbone-feed-sync --type scap --destination-prefix /greenbone-feed --no-permission-change --user root --group root --fail-fast --quiet && GREENBONE_NASL_DIRS=/greenbone-feed/openvas/plugins GREENBONE_NOTUS_DIRS=/greenbone-feed/notus GREENBONE_CERT_DIRS=/greenbone-feed/gvm/cert-data GREENBONE_GVMD_DIRS=/greenbone-feed/gvm/data-objects/gvmd GREENBONE_SCAP_DIRS=/greenbone-feed/gvm/scap-data python3 /work/scripts/generate-source-catalogs.py'
```

The tools image must include `rsync` and a `gvm` user because
`greenbone-feed-sync` switches away from root before syncing Community Feed
data.

Regenerate mapping coverage after changing source mappings:

```sh
ruby scripts/source-mapping-coverage.rb
```

Validate all catalog invariants:

```sh
ruby scripts/validate-catalog.rb
```
