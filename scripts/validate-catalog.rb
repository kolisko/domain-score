#!/usr/bin/env ruby
# frozen_string_literal: true

require "set"
require "yaml"
require "zlib"

ROOT = File.expand_path("..", __dir__)
CATALOG = File.join(ROOT, "catalog", "atomic-checks.yaml")
MANIFEST = File.join(ROOT, "catalog", "generated", "source-catalog-manifest.yaml")
MAPPING = File.join(ROOT, "catalog", "source-to-canonical-map.yaml")
COVERAGE = File.join(ROOT, "catalog", "generated", "source-mapping-coverage.yaml")
ACCESS_POLICY = File.join(ROOT, "catalog", "source-access-policy.yaml")
SOURCE_EVIDENCE = File.join(ROOT, "catalog", "source-research-evidence.yaml")

INDEX_KEYS = {
  "template_rule_index" => "templates",
  "json_id_index" => "checks",
  "plugin_rule_index" => "rules",
  "subtest_index" => "subtests",
  "feed_capability_index" => "feed_streams",
  "greenbone_nvt_index" => "nvts",
  "greenbone_notus_advisory_index" => "advisories",
  "greenbone_cert_advisory_index" => "advisories",
  "greenbone_gvmd_data_object_index" => "objects",
  "greenbone_scap_cve_index" => "cves",
  "provider_index" => "providers",
  "expectation_index" => "expectations",
  "api_field_index" => "fields",
  "reputation_code_index" => "codes",
  "capability_index" => "capabilities"
}.freeze

ACCESS_VALUES = %w[
  open_source_free
  free_public_no_key
  free_with_optional_key
  credentials_required
  paid
  not_packaged_yet
].freeze

def load_yaml(path)
  if path.end_with?(".gz")
    return YAML.safe_load(Zlib::GzipReader.open(path, &:read), permitted_classes: [], aliases: false)
  end
  YAML.load_file(path)
end

def assert(condition, message)
  raise message unless condition
end

catalog = load_yaml(CATALOG)
checks = catalog.fetch("checks")
canonical_ids = checks.map { |check| check.fetch("id") }
duplicate_ids = canonical_ids.group_by(&:itself).select { |_id, values| values.size > 1 }.keys
assert(duplicate_ids.empty?, "duplicate canonical check ids: #{duplicate_ids.join(", ")}")

manifest = load_yaml(MANIFEST)
expected_source_items = 0
manifest.fetch("sources").each do |source|
  index_key = INDEX_KEYS.fetch(source.fetch("index_type"))
  index = load_yaml(File.join(ROOT, source.fetch("path")))
  actual = index.fetch(index_key).size
  expected = source.fetch("count")
  assert(actual == expected, "manifest count mismatch for #{source.fetch("source")}: #{actual} != #{expected}")
  expected_source_items += actual
end

mapping = load_yaml(MAPPING)
mapping_targets = mapping.fetch("mappings").map { |entry| entry.fetch("canonical_id") }.uniq
missing_targets = mapping_targets - canonical_ids
assert(missing_targets.empty?, "mapping targets missing in canonical catalog: #{missing_targets.join(", ")}")

coverage = load_yaml(COVERAGE)
assert(
  coverage.fetch("source_items") == expected_source_items,
  "coverage source_items mismatch: #{coverage.fetch("source_items")} != #{expected_source_items}"
)
unmapped = coverage.fetch("coverage_by_source").select { |_source, stats| stats.fetch("unmapped") != 0 }
assert(unmapped.empty?, "source mapping coverage has unmapped items: #{unmapped.inspect}")

access_policy = load_yaml(ACCESS_POLICY)
policy_ids = access_policy.fetch("sources").map { |source| source.fetch("id") }
duplicate_policy_ids = policy_ids.group_by(&:itself).select { |_id, values| values.size > 1 }.keys
assert(duplicate_policy_ids.empty?, "duplicate access policy source ids: #{duplicate_policy_ids.join(", ")}")
bad_access_values = access_policy.fetch("sources").reject { |source| ACCESS_VALUES.include?(source.fetch("access")) }
assert(bad_access_values.empty?, "invalid access values: #{bad_access_values.map { |source| [source.fetch("id"), source.fetch("access")] }.inspect}")

source_evidence = load_yaml(SOURCE_EVIDENCE)
evidence_ids = source_evidence.fetch("sources").map { |source| source.fetch("id") }
duplicate_evidence_ids = evidence_ids.group_by(&:itself).select { |_id, values| values.size > 1 }.keys
assert(duplicate_evidence_ids.empty?, "duplicate source evidence ids: #{duplicate_evidence_ids.join(", ")}")
missing_evidence = policy_ids - evidence_ids
extra_evidence = evidence_ids - policy_ids
assert(missing_evidence.empty?, "access policy sources missing research evidence: #{missing_evidence.join(", ")}")
assert(extra_evidence.empty?, "research evidence sources missing access policy: #{extra_evidence.join(", ")}")

evidence_by_id = source_evidence.fetch("sources").to_h { |source| [source.fetch("id"), source] }
access_policy.fetch("sources").each do |policy|
  evidence = evidence_by_id.fetch(policy.fetch("id"))
  assert(
    evidence.fetch("access_class") == policy.fetch("access"),
    "source #{policy.fetch("id")} access mismatch: policy=#{policy.fetch("access")} evidence=#{evidence.fetch("access_class")}"
  )
  policy_catalogs = policy.fetch("generated_catalogs").to_set
  evidence_catalogs = evidence.fetch("generated_catalogs").to_set
  assert(
    evidence_catalogs == policy_catalogs,
    "source #{policy.fetch("id")} generated catalog mismatch: policy=#{policy_catalogs.to_a.sort.join(", ")} evidence=#{evidence_catalogs.to_a.sort.join(", ")}"
  )
end

source_evidence.fetch("sources").each do |source|
  urls = source.fetch("source_urls")
  assert(!urls.empty?, "research evidence source #{source.fetch("id")} has no source_urls")
  bad_urls = urls.reject { |url| url.start_with?("https://") }
  assert(bad_urls.empty?, "research evidence source #{source.fetch("id")} has non-https urls: #{bad_urls.join(", ")}")
  source.fetch("generated_catalogs").each do |path|
    assert(File.exist?(File.join(ROOT, path)), "research evidence source #{source.fetch("id")} references missing generated catalog #{path}")
  end
end

puts "catalog validation ok"
puts "canonical_checks=#{canonical_ids.size}"
puts "manifest_sources=#{manifest.fetch("sources").size}"
puts "mapping_rules=#{mapping.fetch("mappings").size}"
puts "source_items=#{coverage.fetch("source_items")}"
puts "access_policy_sources=#{policy_ids.size}"
puts "source_evidence_sources=#{evidence_ids.size}"
