#!/usr/bin/env ruby
# frozen_string_literal: true

require "csv"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"
require "timeout"
require "yaml"

ROOT = File.expand_path("..", __dir__)
KNOWN_TOOLS = %w[subfinder httpx naabu nuclei amass testssl zap internetnl greenbone].freeze

options = {
  binary: "/Users/kolisko/Downloads/domain-score",
  target: "example.com",
  catalog: File.join(ROOT, "catalog", "atomic-checks.yaml"),
  fixture_cache: File.join(ROOT, "testdata", "release-audit", "tool-cache"),
  out: File.join(Dir.home, ".domain-score", "audit-runs", Time.now.utc.strftime("%Y%m%dT%H%M%SZ")),
  timeout: 45,
  limit: nil,
  fail_on_fake: true
}

OptionParser.new do |parser|
  parser.banner = "Usage: scripts/audit-release-checks.rb [options]"
  parser.on("--binary PATH", "Installed release binary to execute") { |v| options[:binary] = v }
  parser.on("--target DOMAIN", "Target for internal checks") { |v| options[:target] = v }
  parser.on("--catalog PATH", "Atomic checks catalog YAML") { |v| options[:catalog] = v }
  parser.on("--fixture-cache PATH", "Existing tool cache with raw/") { |v| options[:fixture_cache] = v }
  parser.on("--out DIR", "Audit output directory") { |v| options[:out] = v }
  parser.on("--timeout SECONDS", Integer, "Per-check command timeout") { |v| options[:timeout] = v }
  parser.on("--limit N", Integer, "Limit number of checks for smoke testing") { |v| options[:limit] = v }
  parser.on("--allow-fake", "Exit 0 even when fake results are found") { options[:fail_on_fake] = false }
end.parse!

def load_checks(path)
  data = YAML.load_file(path)
  data.fetch("checks")
end

def implemented_by(check)
  check["implemented_by"].is_a?(Hash) ? check["implemented_by"] : {}
end

def tool_names(check)
  Array(implemented_by(check)["tools"]).select { |tool| KNOWN_TOOLS.include?(tool) }
end

def source_labels(check)
  by = implemented_by(check)
  labels = []
  Array(by["internal_check_ids"]).each { |id| labels << "internal:#{id}" }
  Array(by["internal_results"]).each { |id| labels << "internal:#{id}" }
  tool_names(check).each { |tool| labels << "tool:#{tool}" }
  labels
end

def command_for(check, options)
  cmd = [
    options[:binary],
    "scan",
    options[:target],
    "--check",
    check.fetch("id"),
    "--format",
    "json",
    "--no-color",
    "--timeout",
    "3s"
  ]
  tools = tool_names(check)
  if tools.any? && !implemented_by(check).key?("internal_check_ids")
    cmd += [
      "--tools",
      tools.join(","),
      "--tool-runtime",
      "cache",
      "--tools-cache-dir",
      options[:runtime_fixture_cache],
      "--tools-pull",
      "never",
      "--tools-timeout",
      "5s"
    ]
  end
  cmd
end

def safe_name(id)
  id.gsub(/[^A-Za-z0-9_.-]/, "_")
end

def run_command(cmd, out_dir, timeout)
  FileUtils.mkdir_p(out_dir)
  full = cmd + ["--out", out_dir]
  env = {"DOMAIN_SCORE_SKIP_UPDATE_CHECK" => "1"}
  stdout = +""
  stderr = +""
  status = nil
  timed_out = false
  Timeout.timeout(timeout) do
    stdout, stderr, status = Open3.capture3(env, *full)
  end
  {
    command: full,
    exit_code: status.exitstatus,
    stdout: stdout,
    stderr: stderr,
    timed_out: timed_out
  }
rescue Timeout::Error
  {
    command: full,
    exit_code: nil,
    stdout: stdout,
    stderr: stderr,
    timed_out: true
  }
end

def read_report(out_dir)
  path = File.join(out_dir, "report.json")
  return nil unless File.file?(path)

  JSON.parse(File.read(path))
end

def result_for(report, check_id)
  return nil unless report

  report.fetch("results", []).find { |result| result["check_id"] == check_id }
end

def evidence_count(result)
  return 0 unless result

  evidence = result["evidence"]
  return 0 unless evidence.is_a?(Hash)

  count = 0
  count += evidence.fetch("count", 0).to_i if evidence.key?("count")
  count += Array(evidence["findings"]).size if evidence["findings"].is_a?(Array)
  count += Array(evidence["records"]).size if evidence["records"].is_a?(Array)
  count += Array(evidence["raw_files"]).size if evidence["raw_files"].is_a?(Array)
  count += evidence.keys.size if count.zero?
  count
end

def raw_files(result, report)
  files = []
  evidence = result && result["evidence"].is_a?(Hash) ? result["evidence"] : {}
  files.concat(Array(evidence["raw_files"]))
  tools = report && report.dig("evidence", "tools").is_a?(Hash) ? report.dig("evidence", "tools") : {}
  files.concat(Array(tools["raw_files"]))
  files.uniq
end

def verdict(check, run, report, result)
  return ["command_timeout", "command timed out"] if run[:timed_out]
  return ["command_error", "command exited #{run[:exit_code]} without report"] if run[:exit_code].to_i != 0 && report.nil?
  return ["missing_result", "report does not contain requested check id"] unless result

  status = result["status"]
  coverage = check["coverage_status"]
  evidence = result["evidence"].is_a?(Hash) ? result["evidence"] : {}
  reason = evidence["reason"].to_s
  count = evidence_count(result)

  if status == "pass"
    return ["fake_result", "planned/external_raw check returned PASS"] if %w[planned external_raw].include?(coverage)
    return ["fake_result", "PASS has no evidence"] if count.zero?
    return ["real_pass", reason.empty? ? "PASS has evidence" : reason]
  end

  if status == "fail"
    return count.zero? ? ["fake_result", "FAIL has no evidence"] : ["real_fail", "FAIL has evidence"]
  end

  if status == "warn"
    return count.zero? ? ["fake_result", "WARN has no evidence"] : ["real_warn", "WARN has evidence"]
  end

  if status == "error"
    return ["tool_unavailable", reason.empty? ? result["recommendation"].to_s : reason] if source_labels(check).any? { |s| s =~ /tool:(internetnl|greenbone)/ }
    return ["command_error", reason.empty? ? result["error"].to_s : reason]
  end

  if status == "not_applicable"
    return ["unsupported", reason.empty? ? result["recommendation"].to_s : reason]
  end

  ["unknown", "unknown status #{status.inspect}"]
end

checks = load_checks(options[:catalog])
checks = checks.first(options[:limit]) if options[:limit]

FileUtils.mkdir_p(options[:out])
options[:runtime_fixture_cache] = File.join(options[:out], "fixture-cache")
FileUtils.rm_rf(options[:runtime_fixture_cache])
FileUtils.mkdir_p(options[:runtime_fixture_cache])
FileUtils.cp_r(File.join(options[:fixture_cache], "raw"), options[:runtime_fixture_cache])
version_stdout, version_stderr, version_status = Open3.capture3(options[:binary], "version")
unless version_status.success?
  warn "Could not execute #{options[:binary]} version: #{version_stderr}"
  exit 2
end

rows = []
checks.each_with_index do |check, index|
  id = check.fetch("id")
  run_dir = File.join(options[:out], "runs", format("%03d-%s", index + 1, safe_name(id)))
  cmd = command_for(check, options)
  run = run_command(cmd, run_dir, options[:timeout])
  report = read_report(run_dir)
  result = result_for(report, id)
  verdict_name, verdict_reason = verdict(check, run, report, result)
  rows << {
    "index" => index + 1,
    "check_id" => id,
    "category" => check["category"],
    "coverage_status" => check["coverage_status"],
    "source" => source_labels(check).join(","),
    "command" => run[:command].join(" "),
    "exit_code" => run[:exit_code],
    "timed_out" => run[:timed_out],
    "status" => result && result["status"],
    "score" => report && report.dig("score", "overall"),
    "grade" => report && report.dig("score", "grade"),
    "evidence_count" => evidence_count(result),
    "raw_files" => raw_files(result, report).join(","),
    "verdict" => verdict_name,
    "verdict_reason" => verdict_reason,
    "run_dir" => run_dir
  }
  warn format("[%3d/%3d] %-46s %-14s %s", index + 1, checks.size, id, result && result["status"], verdict_name)
end

summary = rows.each_with_object(Hash.new(0)) { |row, acc| acc[row["verdict"]] += 1 }
metadata = {
  "generated_at" => Time.now.utc.iso8601,
  "binary" => options[:binary],
  "version" => version_stdout.strip,
  "target" => options[:target],
  "catalog" => options[:catalog],
  "fixture_cache" => options[:fixture_cache],
  "runtime_fixture_cache" => options[:runtime_fixture_cache],
  "checks" => rows.size,
  "summary" => summary
}

File.write(File.join(options[:out], "audit.json"), JSON.pretty_generate({"metadata" => metadata, "checks" => rows}) + "\n")

CSV.open(File.join(options[:out], "audit.csv"), "w") do |csv|
  csv << rows.first.keys
  rows.each { |row| csv << row.values }
end

markdown = +"# Domain Score Release Atomic Check Audit\n\n"
markdown << "- Generated: #{metadata["generated_at"]}\n"
markdown << "- Binary: `#{metadata["version"]}`\n"
markdown << "- Target: `#{metadata["target"]}`\n"
markdown << "- Checks: #{metadata["checks"]}\n\n"
markdown << "## Summary\n\n"
summary.sort.each { |name, count| markdown << "- `#{name}`: #{count}\n" }
markdown << "\n## Fake Results\n\n"
fake_rows = rows.select { |row| row["verdict"] == "fake_result" }
if fake_rows.empty?
  markdown << "No fake results detected.\n"
else
  markdown << "| Check | Status | Coverage | Reason |\n"
  markdown << "| --- | --- | --- | --- |\n"
  fake_rows.each do |row|
    markdown << "| `#{row["check_id"]}` | #{row["status"]} | #{row["coverage_status"]} | #{row["verdict_reason"]} |\n"
  end
end
markdown << "\n## All Checks\n\n"
markdown << "| # | Check | Status | Coverage | Verdict |\n"
markdown << "| ---: | --- | --- | --- | --- |\n"
rows.each do |row|
  markdown << "| #{row["index"]} | `#{row["check_id"]}` | #{row["status"]} | #{row["coverage_status"]} | #{row["verdict"]} |\n"
end
File.write(File.join(options[:out], "audit.md"), markdown)

puts "audit: #{options[:out]}"
puts "binary: #{metadata["version"]}"
puts "checks: #{rows.size}"
summary.sort.each { |name, count| puts "#{name}: #{count}" }

if options[:fail_on_fake] && summary["fake_result"].positive?
  exit 1
end
