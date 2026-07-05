#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "set"
require "yaml"

ROOT = File.expand_path("..", __dir__)
GENERATED = File.join(ROOT, "catalog", "generated")
CATALOG = File.join(ROOT, "catalog", "atomic-checks.yaml")
MAPPING = File.join(ROOT, "catalog", "source-to-canonical-map.yaml")
MANIFEST = File.join(GENERATED, "source-catalog-manifest.yaml")
OUTPUT = File.join(GENERATED, "source-mapping-coverage.yaml")

def yaml_string(value)
  JSON.generate(value.to_s)
end

def load_yaml(path)
  YAML.load_file(path)
end

def source_items(source, path, index_type)
  data = load_yaml(path)
  case index_type
  when "template_rule_index"
    data.fetch("templates").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("group", "") }
    end
  when "json_id_index"
    data.fetch("checks").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => "" }
    end
  when "plugin_rule_index"
    data.fetch("rules").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => "" }
    end
  when "subtest_index"
    data.fetch("subtests").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("category", "") }
    end
  when "feed_capability_index"
    data.fetch("feed_streams").map do |item|
      { "source" => source, "source_id" => item.fetch("stream"), "group" => item.fetch("access", "") }
    end
  when "greenbone_nvt_index"
    data.fetch("nvts").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("family", "") }
    end
  when "greenbone_notus_advisory_index"
    data.fetch("advisories").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("family", "") }
    end
  when "greenbone_cert_advisory_index"
    data.fetch("advisories").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("feed_family", "") }
    end
  when "greenbone_gvmd_data_object_index"
    data.fetch("objects").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("object_type", "") }
    end
  when "greenbone_scap_cve_index"
    data.fetch("cves").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("severity", "") }
    end
  when "provider_index"
    data.fetch("providers").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("access", "") }
    end
  when "expectation_index"
    data.fetch("expectations").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("test", "") }
    end
  when "api_field_index"
    data.fetch("fields").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("object", "") }
    end
  when "reputation_code_index"
    data.fetch("codes").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => item.fetch("code", "") }
    end
  when "capability_index"
    data.fetch("capabilities").map do |item|
      { "source" => source, "source_id" => item.fetch("atomic_id"), "group" => "" }
    end
  else
    raise "unknown index type #{index_type}"
  end
end

def mapping_matches?(mapping, item)
  return false unless mapping.fetch("source") == item.fetch("source")

  case mapping.fetch("match_type")
  when "exact"
    item.fetch("source_id") == mapping.fetch("source_id")
  when "prefix"
    item.fetch("source_id").start_with?(mapping.fetch("source_id"))
  when "group"
    item.fetch("group") == mapping.fetch("source_id") ||
      item.fetch("group").start_with?("#{mapping.fetch("source_id")}/")
  when "stream"
    item.fetch("source_id") == mapping.fetch("source_id")
  else
    raise "unknown match type #{mapping.fetch("match_type")}"
  end
end

def best_mapping(mappings, item)
  matches = mappings.select { |mapping| mapping_matches?(mapping, item) }
  return nil if matches.empty?

  priority = { "exact" => 0, "group" => 1, "stream" => 1, "prefix" => 2 }
  matches.min_by { |mapping| priority.fetch(mapping.fetch("match_type"), 99) }
end

catalog = load_yaml(CATALOG)
canonical_ids = catalog.fetch("checks").map { |item| item.fetch("id") }.to_set
mapping_doc = load_yaml(MAPPING)
mappings = mapping_doc.fetch("mappings")
missing_targets = mappings.map { |mapping| mapping.fetch("canonical_id") }.uniq - canonical_ids.to_a
raise "mapping targets missing in canonical catalog: #{missing_targets.join(", ")}" unless missing_targets.empty?

manifest = load_yaml(MANIFEST)
all_items = manifest.fetch("sources").flat_map do |source|
  source_items(
    source.fetch("source"),
    File.join(ROOT, source.fetch("path")),
    source.fetch("index_type")
  )
end

by_source = {}
mapped_targets = Hash.new(0)
all_items.each do |item|
  bucket = by_source[item.fetch("source")] ||= {
    "total" => 0,
    "mapped" => 0,
    "unmapped" => 0,
    "unmapped_examples" => []
  }
  bucket["total"] += 1
  mapping = best_mapping(mappings, item)
  if mapping
    bucket["mapped"] += 1
    mapped_targets[mapping.fetch("canonical_id")] += 1
  else
    bucket["unmapped"] += 1
    bucket["unmapped_examples"] << item.fetch("source_id") if bucket["unmapped_examples"].size < 25
  end
end

File.open(OUTPUT, "w") do |out|
  out.puts "schema_version: 1"
  out.puts "kind: domain-score.source-mapping-coverage"
  out.puts 'generated_at: "2026-07-05"'
  out.puts "canonical_checks: #{canonical_ids.size}"
  out.puts "source_items: #{all_items.size}"
  out.puts "mapping_rules: #{mappings.size}"
  out.puts "coverage_by_source:"
  by_source.keys.sort.each do |source|
    bucket = by_source.fetch(source)
    out.puts "  #{source}:"
    out.puts "    total: #{bucket.fetch("total")}"
    out.puts "    mapped: #{bucket.fetch("mapped")}"
    out.puts "    unmapped: #{bucket.fetch("unmapped")}"
    out.puts "    unmapped_examples:"
    if bucket.fetch("unmapped_examples").empty?
      out.puts "      []"
    else
      bucket.fetch("unmapped_examples").each do |example|
        out.puts "      - #{yaml_string(example)}"
      end
    end
  end
  out.puts "top_canonical_targets:"
  mapped_targets.sort_by { |target, count| [-count, target] }.first(50).each do |target, count|
    out.puts "  - canonical_id: #{yaml_string(target)}"
    out.puts "    mapped_source_items: #{count}"
  end
end

puts "wrote #{OUTPUT}"
