# Tool Research Log

This file records evidence used to expand `catalog/atomic-checks.yaml`.

The catalog is intentionally not a list of runtime findings. Values such as
ports, URLs, hosts, IP addresses, banners and exact versions stay in scan
findings. The catalog contains the audited condition types.

Generated source catalog manifest:

```text
catalog/generated/source-catalog-manifest.yaml
```

Curated source-to-canonical normalization map:

```text
catalog/source-to-canonical-map.yaml
catalog/generated/source-mapping-coverage.yaml
catalog/source-access-policy.yaml
```

Catalog validator:

```text
scripts/validate-catalog.rb
```

## 2026-07-05 Batch 1

### Tools Confirmed In The Current Runtime

The all-in-one tools image and Dockerfile currently include:

- ProjectDiscovery `subfinder`
- ProjectDiscovery `httpx`
- ProjectDiscovery `naabu`
- ProjectDiscovery `nuclei`
- ProjectDiscovery `nuclei-templates`
- OWASP Amass
- OWASP ZAP Baseline
- `testssl.sh`
- Internet.nl source/public workflow wrapper
- Greenbone client/feed tooling

The pinned tools image inspected for generated source catalogs:

```text
ghcr.io/kolisko/domain-score-tools@sha256:013b814b66d07c5ce9703892d9b0434c35fdbe1e4c9b49d104ab7776ef057f7a
```

### Evidence Collected

ZAP Baseline:

- Official docs: https://www.zaproxy.org/docs/docker/baseline-scan/
- Source pointer from docs: https://github.com/zaproxy/zaproxy/tree/main/docker
- The docs state that baseline runs spidering plus passive scanning and does
  not perform actual attacks.
- The baseline config model uses stable rule ids and can generate a default
  rule config with WARN/FAIL/IGNORE handling.
- Rule ids confirmed from docs include `10010`, `10011`, `10012`, `10015`,
  `10016`, `10017`, `10019`, `10020`, `10021`, `10023`, `10024`, `10025`,
  `10026`, `10027`, `10032`, `10040`, `10105`, `10202`, `2`, `3`, `50001`,
  `90001`, `90011`, `90022`, `90030`, `90033`.

Nuclei:

- Official docs: https://docs.projectdiscovery.io/opensource/nuclei/running
- Runtime help confirms filters by template id, tags, severity and protocol
  type.
- Runtime help lists protocol types: `dns`, `file`, `http`, `headless`,
  `tcp`, `workflow`, `ssl`, `websocket`, `whois`, `code`, `javascript`.
- The inspected image contains 13,419 YAML/YML templates under
  `/opt/nuclei-templates`.
- Generated summary: `catalog/generated/nuclei-template-summary.yaml`.
- Generated source rule index: `catalog/generated/nuclei-template-index.yaml`.
- Observed top-level counts: HTTP 11,024, cloud 663, file 447, code 288,
  network 280, DAST 249, workflows 207, JavaScript 125, SSL 38, DNS 31 and
  headless 24.
- The generated index contains 13,375 template definitions with
  `nuclei.<template-id>` atomic IDs, titles, severities, source paths, groups
  and tags. Forty-four YAML/YML files in the snapshot were not indexed because
  they are not concrete templates with both a top-level `id` and `info.name`
  in the parser's source-catalog model.
- Observed HTTP subgroups: CVEs 4,104, exposed panels 1,513, OSINT 1,078,
  misconfiguration 978, vulnerabilities 942, technologies 895, exposures 696,
  default logins 301, token spray 247 and takeovers 73.
- Observed severity counts: info 5,049, high 2,923, medium 2,808, critical
  1,825, low 505 and unknown 58.
- Observed top-level template groups include `cloud`, `file`, `ssl`,
  `javascript`, `http`, `network`, `dns`, `workflows`, `code` and `dast`.
- Observed relevant subgroups include `cves`, `exposures`,
  `misconfiguration`, `takeovers`, `default-logins`, `exposed-panels`,
  `technologies`, `malware`, `webshell`, `c2` and cloud-provider checks.

ProjectDiscovery httpx/naabu/subfinder:

- Official httpx docs: https://docs.projectdiscovery.io/opensource/httpx/usage
- Generated capability index:
  `catalog/generated/projectdiscovery-capability-index.yaml`.
- Runtime help confirms httpx probes for status code, content length/type,
  redirects, favicon hash, response hashes, JARM, response time, title, server,
  technology detection, CPE, WordPress plugins/themes, WebSocket, IP, CNAME,
  extracted FQDNs, ASN, CDN/WAF, screenshots, HTTP/2, vhost, TLS grab and
  response chains.
- Runtime help confirms naabu port discovery, passive InternetDB mode, host
  discovery, CDN display, service discovery and service-version probes.
- Runtime help confirms subfinder passive subdomain discovery and JSONL source
  attribution.
- Generated Subfinder provider index:
  `catalog/generated/subfinder-provider-index.yaml`.
- Runtime `subfinder -ls` confirms 50 providers and marks providers requiring
  keys/tokens with `*` and providers optionally supporting keys with `~`.
- The generated provider index contains 9 no-key public providers, 3 optional-key
  providers and 38 credentials-required providers.
- Runtime verification of the inspected `v0.6.5` tools image found that the
  `httpx` command currently resolves to the Python HTTPX CLI wrapper instead
  of ProjectDiscovery httpx. The catalog entries remain valid as ProjectDiscovery
  capabilities, but the Docker image should be fixed before relying on runtime
  httpx findings.
- The generated capability index contains 43 capability IDs across subfinder,
  httpx and naabu. These are repeatable evidence outputs, not vulnerability
  rule IDs.

OWASP Amass:

- Generated capability index: `catalog/generated/amass-capability-index.yaml`.
- Generated provider/source index: `catalog/generated/amass-provider-index.yaml`.
- Runtime help confirms Amass v5.1.1 attack surface mapping commands:
  `assoc`, `engine`, `enum`, `subs`, `track` and `viz`.
- Source tree inspected: https://github.com/owasp-amass/amass/tree/master/resources/scripts
- Amass ADS data-source scripts are grouped by `alt`, `api`, `archive`,
  `brute`, `cert`, `crawl`, `dns`, `misc` and `scrape`.
- `amass enum` supports passive/default enumeration, active certificate name
  grabs and zone transfer attempts, altered-name generation, brute forcing,
  ASN/CIDR/address inputs, recursive brute forcing, source include/exclude and
  resolver selection.
- `amass subs` supports displaying discovered names, IPv4/IPv6 addresses and
  ASN summaries from the graph database.
- The generated capability index contains 17 capability IDs for passive
  enumeration, active certificate name grabs, AXFR attempts, altered-name
  generation, brute force, ASN/CIDR/address scope expansion, source control,
  resolver selection, asset tracking and graph visualization.
- The generated provider index contains 97 ADS data-source script entries:
  56 API scripts marked credentials-required, 36 public/no-key source scripts
  and 5 local/open-source generation or DNS source scripts.

testssl.sh:

- Source/docs: https://github.com/testssl/testssl.sh
- Generated source rule index: `catalog/generated/testssl-jsonid-index.yaml`.
- Runtime help confirms standard checks for protocols, cipher categories,
  forward secrecy, server defaults, server preference, headers, client
  simulation and vulnerabilities.
- Runtime help confirms vulnerability checks for Heartbleed, CCS injection,
  Ticketbleed, Opossum, ROBOT, STARTTLS injection, renegotiation, CRIME,
  BREACH, POODLE, TLS fallback, SWEET32, BEAST, LUCKY13, Winshock, FREAK,
  LOGJAM, DROWN and RC4.
- Runtime help confirms STARTTLS protocols including FTP, SMTP, LMTP, POP3,
  IMAP, XMPP, telnet, LDAP, NNTP, sieve, PostgreSQL and MySQL.
- The generated index contains 107 `testssl.<json-id>` atomic IDs extracted
  from `jsonID` and `fileout` usage in the open-source script.

ZAP add-ons:

- Generated source rule index: `catalog/generated/zap-rule-index.yaml`.
- The generated index contains 104 `zap.<pluginid>` atomic IDs extracted from
  English help HTML bundled in the installed ZAP add-ons.
- Passive scan rules from `pscanrules` are marked `safe`; active scan rules
  from `ascanrules` are marked `aggressive`.

Greenbone:

- Official docs:
  https://greenbone.github.io/docs/latest/22.4/container/index.html
- Source/tooling: https://github.com/greenbone/gvm-tools
- Generated capability index:
  `catalog/generated/greenbone-feed-capability-index.yaml`.
- Generated NVT index:
  `catalog/generated/greenbone-nvt-index.yaml.gz`.
- Generated Notus advisory index:
  `catalog/generated/greenbone-notus-advisory-index.yaml.gz`.
- Generated CERT/DFN-CERT advisory index:
  `catalog/generated/greenbone-cert-advisory-index.yaml.gz`.
- Generated GVMD data-object index:
  `catalog/generated/greenbone-gvmd-data-object-index.yaml`.
- Generated SCAP CVE index:
  `catalog/generated/greenbone-scap-cve-index.yaml.gz`.
- The docs describe Greenbone Community Edition as a distributed Docker Compose
  service stack, not a one-shot command.
- Services/data sources described include `gvmd`, `gsad`, `ospd-openvas`,
  `openvasd`, Redis, PostgreSQL, vulnerability tests, Notus data, SCAP data,
  CERT-Bund data, DFN-CERT data, data objects and report formats.
- Atomic source-specific checks should be generated from NVT OIDs, CVEs,
  package vulnerability data and compliance policies once a running feed is
  available.
- Runtime verification of the tools image found `greenbone-feed-sync` 25.3.0,
  `gvm-cli` and `rsync`, but no local NASL/NVT files.
- A Greenbone Community NASL sync to a temporary host cache was verified with
  `greenbone-feed-sync --type nasl`; it downloaded 95,090 NASL files and the
  generator indexed 95,080 NVT OID rules.
- A Greenbone Community Notus sync to the same temporary host cache was verified
  with `greenbone-feed-sync --type notus`; it downloaded 533 `.notus` files and
  the generator indexed 86,723 advisory OID rules.
- A Greenbone Community CERT sync to the same temporary host cache was verified
  with `greenbone-feed-sync --type cert`; it downloaded CERT-Bund and DFN-CERT
  XML feeds and the generator indexed 70,401 advisory rules.
- A Greenbone Community GVMD data sync indexed 23 scan-config, port-list and
  report-format data objects.
- A Greenbone Community SCAP sync downloaded NVD CVE JSON files for 1999-2026;
  the generator indexed 363,055 CVE rules and deliberately kept CPE matches as
  aggregate evidence counts.
- Community feed streams are tracked as `community_free`; Greenbone Enterprise
  Feed is marked `paid`.
- The NVT parser in `scripts/generate-source-catalogs.py` reads synced NASL
  files via `GREENBONE_NASL_DIRS`; the feed files themselves are not stored in
  the repository.
- The Notus parser reads synced advisory/product files via
  `GREENBONE_NOTUS_DIRS`; product and fixed-package references are aggregated
  evidence, not separate atomic checks.
- The CERT parser reads synced XML advisory files via `GREENBONE_CERT_DIRS`;
  CERT-Bund IDs are normalized for source IDs while the original advisory ID is
  preserved as evidence.
- The GVMD data-object parser reads synced scan-config, port-list and
  report-format XML files via `GREENBONE_GVMD_DIRS`.
- The SCAP parser reads synced NVD JSON files via `GREENBONE_SCAP_DIRS`;
  control characters in upstream descriptions are sanitized before YAML output.

Internet.nl:

- Source: https://github.com/internetstandards/Internet.nl
- Public service: https://internet.nl/
- Generated source subtest index:
  `catalog/generated/internetnl-subtest-index.yaml`.
- Source files inspected from the tools image include
  `/opt/internetnl/checks/categories.py`, `/opt/internetnl/checks/scoring.py`,
  `/opt/internetnl/documentation/scoring.md`, `/opt/internetnl/documentation/tls.md`
  and `/opt/internetnl/documentation/rpki.md`.
- Domain Score currently uses the public site workflow for web results.
- Product categories tracked in the catalog: web IPv6, web DNSSEC, web HTTPS,
  web appsec/privacy, web RPKI, mail authentication, mail STARTTLS/DANE and
  mail RPKI.
- The generated index contains 76 active subtests wired into Internet.nl
  categories: web TLS, mail TLS, mail RPKI, mail auth, web appsec/privacy,
  web IPv6, mail DNSSEC, mail IPv6, web RPKI and web DNSSEC.

MDN HTTP Observatory:

- Source: https://github.com/mdn/mdn-http-observatory
- Generated expectation index:
  `catalog/generated/mozilla-observatory-expectation-index.yaml`.
- Source files inspected include `src/constants.js`, `src/types.js`,
  `src/grader/grader.js`, `src/grader/charts.js` and analyzer tests under
  `src/analyzer/tests/`.
- The current analyzer exposes 10 tests: Content Security Policy, Cookies,
  CORS, HTTPS redirection, Referrer-Policy, HSTS, Subresource Integrity,
  X-Content-Type-Options, X-Frame-Options and Cross-Origin-Resource-Policy.
- The generated index contains 66 source-specific expectation IDs using the
  pattern `mozilla_observatory.<expectation>`.

SSL Labs:

- Source/API docs:
  https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md
- Generated API field index:
  `catalog/generated/ssl-labs-api-field-index.yaml`.
- SSL Labs API v4 is a hosted third-party TLS assessment API. It is free under
  SSL Labs terms and registration/rate-limit requirements, but it is not a
  local open-source scanner.
- The generated index contains 64 source-specific API field IDs covering
  endpoint grades, warnings, protocol/cipher quality, certificate chain issues,
  HSTS/preload policy, CT SCT evidence, CAA, revocation, key strength and TLS
  vulnerability signals including Heartbleed, ROBOT/Bleichenbacher, POODLE,
  FREAK, DROWN and padding oracle families.

Public reputation and exposure sources:

- Shodan InternetDB public endpoint: https://internetdb.shodan.io/
- Generated Shodan InternetDB field index:
  `catalog/generated/shodan-internetdb-field-index.yaml`.
- The generated index contains 6 no-key API evidence fields: queried IP, ports,
  CPEs, hostnames, tags and CVE vulnerability identifiers.
- URLhaus public API: https://urlhaus-api.abuse.ch/
- Generated URLhaus host field index:
  `catalog/generated/urlhaus-host-field-index.yaml`.
- The generated index contains 16 host-query evidence fields covering query
  status, host/reference metadata, URL count, blacklist statuses and per-URL
  malware/reporter/tag/takedown fields.
- Spamhaus DBL generated return-code index:
  `catalog/generated/spamhaus-dbl-return-code-index.yaml`.
- The generated index contains 13 DBL DNS return-code labels, including domain
  listing categories and operational/error states that are not positive
  reputation listings.
- SURBL generated return-code index:
  `catalog/generated/surbl-return-code-index.yaml`.
- The generated index contains 7 SURBL bitmask/return-code labels for DM, PH,
  MW, CT, abuse, CR and blocked-access states.
- VirusTotal domain API docs:
  https://docs.virustotal.com/reference/domain-info
- Generated VirusTotal domain field index:
  `catalog/generated/virustotal-domain-field-index.yaml`.
- The generated index contains 25 free/optional-key domain object fields
  covering categorization, last analysis stats/results, community reputation,
  total votes, DNS records, HTTPS certificate, registrar/WHOIS metadata,
  popularity ranks, tags and JARM fingerprint.
- Enterprise-only VirusTotal relationship collections are excluded from the
  generated field catalog and should stay out of the free/open-source path
  unless a user explicitly configures an eligible account.

### Catalog Delta

After this batch:

- canonical catalog checks: 299
- generated Nuclei template checks: 13,375
- generated testssl JSON-ID checks: 107
- generated ZAP rule checks: 104
- generated Internet.nl subtests: 76
- generated Greenbone feed capability entries: 9 feed streams
- generated Greenbone NVT OID entries: 95,080 from the free Community NASL feed
- generated Greenbone Notus advisory OID entries: 86,723 from the free Community Notus feed
- generated Greenbone CERT/DFN-CERT advisory entries: 70,401 from the free Community CERT feed
- generated Greenbone GVMD data-object entries: 23 from the free Community data feed
- generated Greenbone SCAP CVE entries: 363,055 from the free Community SCAP feed
- generated ProjectDiscovery capabilities: 43
- generated Amass capabilities: 17
- generated Subfinder providers: 50
- generated Amass ADS provider/source scripts: 97
- generated MDN HTTP Observatory expectations: 66
- generated SSL Labs API field signals: 64
- generated Shodan InternetDB API field signals: 6
- generated URLhaus host API field signals: 16
- generated Spamhaus DBL return-code signals: 13
- generated SURBL return-code signals: 7
- generated VirusTotal domain API field signals: 25
- curated source-to-canonical mappings: 558
- source mapping coverage: 629,357 of 629,357 source items mapped to an existing
  canonical check
- ZAP source mapping coverage: 104 of 104 plugin IDs mapped by exact
  source-to-canonical rules; the broad ZAP fallback remains only as a safety net
  for future add-ons.
- testssl source mapping coverage: 107 of 107 JSON-ID fields mapped by exact
  source-to-canonical rules.
- SSL Labs source mapping coverage: 64 of 64 public API fields mapped by exact
  source-to-canonical rules.
- Nuclei source mapping coverage: 13,375 of 13,375 templates mapped, with the
  broad `vulnerability.nuclei_template_match` fallback reduced to 0 current
  templates.
- Greenbone source mapping coverage: current NVT and Notus source items no
  longer map to broad fallback buckets; `vulnerability.greenbone_nvt_match` and
  `vulnerability.notus_package_vulnerability` are 0 for the current generated
  source catalogs.
- source access policy entries: free/open-source/no-key/API-key/paid
  classification for tools and public intelligence sources
- catalog validator: `scripts/validate-catalog.rb`
- implemented: 70
- partial: 17
- external_raw: 124
- planned: 88

New canonical checks added in this batch include:

- `web.cross_site_scripting_signal`, used for normalizing XSS-oriented ZAP and
  Nuclei findings.
- `web.zap_passive_or_active_alert`, used as a safe fallback for ZAP plugin IDs
  that need more specific classification later.
- `tls.testssl_signal_requires_review`, used as a fallback for detailed
  testssl JSON IDs that need more specific classification later.
- `inventory.tool_capability_metadata`, used for non-finding capability,
  feed-stream or scan-control metadata.
- ZAP-derived web application and exposure checks such as
  `web.sql_injection_signal`, `web.path_traversal_signal`,
  `web.remote_file_include_signal`, `web.sensitive_file_disclosure`,
  `web.browser_storage_sensitive_disclosure`,
  `web.server_side_template_injection_signal` and
  `vulnerability.remote_code_execution_signal`.
- TLS/certificate/HTTP transport checks from testssl and SSL Labs such as
  `tls.alpn_protocols_advertised`, `tls.dh_group_policy`,
  `tls.session_ticket_policy`, `tls.early_data_enabled`,
  `tls.ocsp_stapling_present`, `tls.certificate_key_size_policy`,
  `tls.certificate_signature_algorithm_policy`, `tls.rc4_enabled`,
  `tls.sweet32_vulnerable`, `tls.poodle_vulnerable`,
  `http.hpkp_header_present`, `http.clock_skew_detected` and
  `vulnerability.debian_weak_key_signal`.
- Nuclei-derived template families such as `nuclei.http_misconfiguration`,
  `nuclei.web_vulnerability_signal`, `nuclei.osint_public_exposure`,
  `nuclei.technology_detection`, `nuclei.token_spray_or_credential_attack`,
  `nuclei.network_misconfiguration`, `nuclei.network_enumeration_signal`,
  `nuclei.dns_template_signal`, `nuclei.fuzzing_probe_signal`,
  `nuclei.known_advisory_template` and
  `nuclei.miscellaneous_public_signal`.
- Greenbone-derived feed families such as
  `greenbone.vendor_security_advisory_check`,
  `greenbone.web_application_vulnerability`, `greenbone.product_detection`,
  `greenbone.denial_of_service_check`,
  `greenbone.policy_or_compliance_check`,
  `greenbone.network_device_security_check`,
  `greenbone.tls_or_crypto_check`, `greenbone.scap_cve_metadata`,
  `greenbone.cert_bund_advisory` and `greenbone.dfn_cert_advisory`.

### Remaining Research

- The current all-in-one tools image is now represented by either a generated
  rule/subtest index or a generated capability/feed index for Nuclei, ZAP,
  testssl.sh, Internet.nl, ProjectDiscovery, Amass and Greenbone.
- MDN HTTP Observatory and SSL Labs public/API result vocabularies are now
  represented by generated source catalogs and mapped into canonical checks.
- Subfinder providers and Amass ADS data-source scripts are now represented by
  generated provider catalogs with no-key/optional-key/credentials-required
  classification.
- Shodan InternetDB, URLhaus, Spamhaus DBL and SURBL public/no-key evidence
  vocabularies are now represented by generated source catalogs.
- VirusTotal domain API free/optional-key evidence vocabulary is now represented
  by a generated source catalog; enterprise-only relationship collections are
  excluded.
- Where justified by stable metadata, promote high-value Nuclei template IDs,
  Greenbone NVT OIDs or CVE IDs into first-class canonical checks rather than
  source-family buckets.
- Regenerate Greenbone source-specific indexes whenever the Community Feed cache
  is refreshed.
- Keep expanding open-source/free reputation sources and update
  `catalog/source-access-policy.yaml` whenever a source is no-key, API-key,
  credentials-required or paid.
