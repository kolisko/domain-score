#!/usr/bin/env python3
"""Generate source-specific atomic check catalogs from installed tools.

This script is meant to run inside the all-in-one tools image with the project
mounted at /work. It intentionally uses only the Python standard library.
"""

from __future__ import annotations

import collections
import ast
import gzip
import html
import json
import os
import pathlib
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile
from typing import Iterable


PROJECT_ROOT = pathlib.Path("/work")
NUCLEI_ROOT = pathlib.Path("/opt/nuclei-templates")
TESTSSL_SCRIPT = pathlib.Path("/opt/testssl.sh/testssl.sh")
ZAP_PLUGIN_DIR = pathlib.Path("/zap/plugin")
INTERNETNL_ROOT = pathlib.Path("/opt/internetnl")
INTERNETNL_CATEGORIES = INTERNETNL_ROOT / "checks/categories.py"
INTERNETNL_SCORING = INTERNETNL_ROOT / "checks/scoring.py"
SOURCE_IMAGE = (
    "ghcr.io/kolisko/domain-score-tools@"
    "sha256:013b814b66d07c5ce9703892d9b0434c35fdbe1e4c9b49d104ab7776ef057f7a"
)
GENERATED_AT = "2026-07-05"


def yaml_string(value: object) -> str:
    text = "" if value is None else str(value)
    text = "".join(
        ch if (ch in "\t\n\r" or ord(ch) >= 32) and not (0x7F <= ord(ch) <= 0x9F) else " "
        for ch in text
    )
    text = text.replace("'", "''")
    return f"'{text}'"


def scalar(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value[0] in ("'", '"') and value[-1:] == value[0]:
        return value[1:-1]
    if " #" in value:
        value = value.split(" #", 1)[0].strip()
    return value


def parse_tags(value: str) -> list[str]:
    value = scalar(value)
    if not value:
        return []
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1].strip()
        if not value:
            return []
    return [scalar(part.strip()) for part in value.split(",") if part.strip()]


def open_output(path: pathlib.Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".gz":
        return gzip.open(path, "wt", encoding="utf-8")
    return path.open("w", encoding="utf-8")


def nuclei_paths() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for pattern in ("*.yaml", "*.yml"):
        paths.extend(NUCLEI_ROOT.rglob(pattern))
    return sorted(paths)


def parse_nuclei_template(path: pathlib.Path) -> dict[str, object] | None:
    text = path.read_text(errors="ignore")
    template_id: str | None = None
    name: str | None = None
    severity: str | None = None
    tags: list[str] = []
    in_info = False
    info_indent = 0

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^id:\s*(.+?)\s*$", line)
        if match and template_id is None:
            template_id = scalar(match.group(1))
            continue
        match = re.match(r"^(\s*)info:\s*$", line)
        if match:
            in_info = True
            info_indent = len(match.group(1))
            continue
        if not in_info:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= info_indent and not line.startswith(" "):
            in_info = False
            continue
        match = re.match(r"^\s+name:\s*(.+?)\s*$", line)
        if match and name is None:
            name = scalar(match.group(1))
            continue
        match = re.match(r"^\s+severity:\s*(.+?)\s*$", line)
        if match and severity is None:
            severity = scalar(match.group(1)).lower()
            continue
        match = re.match(r"^\s+tags:\s*(.+?)\s*$", line)
        if match and not tags:
            tags = parse_tags(match.group(1))[:30]

    if not template_id or not name:
        return None

    relative_path = str(path.relative_to(NUCLEI_ROOT))
    parts = relative_path.split("/")
    top_level_group = parts[0] if parts else ""
    group = "/".join(parts[:2]) if len(parts) > 1 else top_level_group
    return {
        "atomic_id": f"nuclei.{template_id}",
        "source_template_id": template_id,
        "title": name,
        "severity": severity or "unknown",
        "source_path": relative_path,
        "top_level_group": top_level_group,
        "group": group,
        "tags": tags,
    }


def write_scalar_map(out, name: str, counter: collections.Counter[str]) -> None:
    out.write(f"{name}:\n")
    for key, value in counter.most_common():
        out.write(f"  {key}: {value}\n")


def write_nuclei_index() -> None:
    paths = nuclei_paths()
    templates = [item for path in paths if (item := parse_nuclei_template(path))]
    duplicate_ids = [
        key
        for key, value in collections.Counter(
            item["source_template_id"] for item in templates
        ).items()
        if value > 1
    ]
    severity_counts = collections.Counter(str(item["severity"]) for item in templates)
    group_counts = collections.Counter(str(item["top_level_group"]) for item in templates)

    output = PROJECT_ROOT / "catalog/generated/nuclei-template-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.nuclei-template-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"templates_count_observed: {len(paths)}\n")
        out.write(f"templates_indexed: {len(templates)}\n")
        out.write(f"duplicate_template_ids: {len(duplicate_ids)}\n")
        out.write("notes:\n")
        out.write(
            "  - Source-specific atomic IDs use the pattern nuclei.<template-id>.\n"
        )
        out.write(
            "  - This file is generated from the open-source nuclei-templates snapshot in the tools image.\n"
        )
        out.write(
            "  - Runtime matches are findings; this file is the product/source rule catalog.\n"
        )
        write_scalar_map(out, "severity_counts", severity_counts)
        write_scalar_map(out, "top_level_groups", group_counts)
        out.write("templates:\n")
        for item in templates:
            out.write(f"  - atomic_id: {yaml_string(item['atomic_id'])}\n")
            out.write(
                f"    source_template_id: {yaml_string(item['source_template_id'])}\n"
            )
            out.write(f"    title: {yaml_string(item['title'])}\n")
            out.write(f"    severity: {yaml_string(item['severity'])}\n")
            out.write(f"    source_path: {yaml_string(item['source_path'])}\n")
            out.write(f"    top_level_group: {yaml_string(item['top_level_group'])}\n")
            out.write(f"    group: {yaml_string(item['group'])}\n")
            tags = item["tags"]
            if isinstance(tags, list) and tags:
                out.write("    tags:\n")
                for tag in tags:
                    out.write(f"      - {yaml_string(tag)}\n")
            else:
                out.write("    tags: []\n")
    print(f"wrote {output} ({len(templates)} templates)")


TESTSSL_TITLES = {
    "ALPN": "Application-Layer Protocol Negotiation support",
    "BEAST": "BEAST vulnerability signal",
    "BREACH": "BREACH compression vulnerability signal",
    "CCS": "OpenSSL CCS injection vulnerability signal",
    "CRIME_TLS": "TLS CRIME compression vulnerability signal",
    "DROWN": "DROWN vulnerability signal",
    "FREAK": "FREAK export cipher vulnerability signal",
    "heartbleed": "Heartbleed vulnerability signal",
    "LOGJAM": "Logjam vulnerability signal",
    "LUCKY13": "Lucky13 vulnerability signal",
    "POODLE_SSL": "POODLE SSL vulnerability signal",
    "POODLE_TLS": "POODLE TLS vulnerability signal",
    "ROBOT": "ROBOT vulnerability signal",
    "SWEET32": "SWEET32 64-bit block cipher vulnerability signal",
    "ticketbleed": "Ticketbleed vulnerability signal",
    "winshock": "Winshock vulnerability signal",
}


def testssl_title(identifier: str) -> str:
    if identifier in TESTSSL_TITLES:
        return TESTSSL_TITLES[identifier]
    words = identifier.replace("_", " ").replace("-", " ").strip()
    return words[:1].upper() + words[1:] if words else identifier


def testssl_category(identifier: str) -> str:
    lowered = identifier.lower()
    if lowered.startswith("cert") or "certificate" in lowered or lowered == "ocsp_stapling":
        return "tls_certificate"
    if lowered.startswith("http") or lowered.startswith("hsts") or lowered.startswith("hpkp") or lowered.startswith("cookie"):
        return "http_tls_headers"
    if lowered in {
        "heartbleed",
        "ccs",
        "ticketbleed",
        "robot",
        "opossum",
        "winshock",
        "drown",
        "freak",
        "logjam",
        "lucky13",
        "sweet32",
        "beast",
        "breach",
        "crime_tls",
        "poodle_ssl",
        "poodle_tls",
        "rc4",
    }:
        return "tls_vulnerability"
    if "cipher" in lowered or lowered in {"fs", "dh_groups", "pre_128cipher"}:
        return "tls_cipher_policy"
    if lowered.startswith("tls") or lowered.startswith("ssl") or lowered in {"fallback_scsv", "early_data", "grease", "quic", "npn", "alpn"}:
        return "tls_protocol"
    return "tls_misc"


def testssl_severity(identifier: str) -> str:
    category = testssl_category(identifier)
    if category == "tls_vulnerability":
        return "high"
    if category in {"tls_cipher_policy", "tls_protocol"}:
        return "medium"
    return "low"


def extract_testssl_ids() -> list[str]:
    text = TESTSSL_SCRIPT.read_text(errors="ignore")
    identifiers: set[str] = set()
    for match in re.finditer(r'(?:local[ \t]+)?jsonID="([^"]+)"', text):
        value = match.group(1)
        if "$" not in value and "`" not in value:
            identifiers.add(value)
    for match in re.finditer(r'fileout[ \t]+"([A-Za-z0-9_:-]+)"', text):
        identifiers.add(match.group(1))
    return sorted(identifiers)


def write_testssl_index() -> None:
    identifiers = extract_testssl_ids()
    category_counts = collections.Counter(testssl_category(identifier) for identifier in identifiers)
    output = PROJECT_ROOT / "catalog/generated/testssl-jsonid-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.testssl-jsonid-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"jsonids_indexed: {len(identifiers)}\n")
        out.write("notes:\n")
        out.write(
            "  - Source-specific atomic IDs use the pattern testssl.<json-id>.\n"
        )
        out.write(
            "  - IDs were extracted from testssl.sh fileout/jsonID usage in the open-source script.\n"
        )
        out.write(
            "  - Runtime values such as ciphers, protocols and CVEs remain finding evidence.\n"
        )
        write_scalar_map(out, "category_counts", category_counts)
        out.write("checks:\n")
        for identifier in identifiers:
            out.write(f"  - atomic_id: {yaml_string('testssl.' + identifier)}\n")
            out.write(f"    source_json_id: {yaml_string(identifier)}\n")
            out.write(f"    title: {yaml_string(testssl_title(identifier))}\n")
            out.write(f"    category: {yaml_string(testssl_category(identifier))}\n")
            out.write(f"    severity: {yaml_string(testssl_severity(identifier))}\n")
            out.write("    mode: aggressive\n")
    print(f"wrote {output} ({len(identifiers)} JSON IDs)")


def zap_severity(title: str) -> str:
    lowered = title.lower()
    high_terms = ("cross site scripting", "sql injection", "remote code", "vulnerable")
    medium_terms = (
        "content security policy",
        "anti-clickjacking",
        "cookie",
        "csrf",
        "private",
        "sensitive",
        "information disclosure",
    )
    if any(term in lowered for term in high_terms):
        return "high"
    if any(term in lowered for term in medium_terms):
        return "medium"
    return "low"


def extract_zap_help_rules() -> list[dict[str, str]]:
    rules: dict[str, dict[str, str]] = {}
    for archive_path in sorted(ZAP_PLUGIN_DIR.glob("*.zap")):
        try:
            archive = zipfile.ZipFile(archive_path)
        except zipfile.BadZipFile:
            continue
        for name in archive.namelist():
            if "help_" in name:
                continue
            is_help = "/help/contents/" in name or "/resources/help/contents/" in name
            if not is_help or not name.endswith(".html"):
                continue
            text = archive.read(name).decode("utf-8", "ignore")
            for match in re.finditer(
                r"<[Hh]2[^>]*id=[\"']id-(\d+)[\"'][^>]*>(.*?)</[Hh]2>",
                text,
                re.S,
            ):
                plugin_id = match.group(1)
                title = html.unescape(re.sub(r"<[^>]+>", "", match.group(2))).strip()
                if not title:
                    continue
                rules[plugin_id] = {
                    "atomic_id": f"zap.{plugin_id}",
                    "plugin_id": plugin_id,
                    "title": title,
                    "addon": archive_path.name,
                    "source_path": name,
                    "severity": zap_severity(title),
                    "mode": "aggressive"
                    if archive_path.name.startswith("ascanrules-")
                    else "safe",
                }
    return [rules[key] for key in sorted(rules, key=lambda value: int(value))]


def write_zap_index() -> None:
    rules = extract_zap_help_rules()
    addon_counts = collections.Counter(rule["addon"] for rule in rules)
    output = PROJECT_ROOT / "catalog/generated/zap-rule-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.zap-rule-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"rules_indexed: {len(rules)}\n")
        out.write("notes:\n")
        out.write("  - Source-specific atomic IDs use the pattern zap.<pluginid>.\n")
        out.write(
            "  - IDs and titles were extracted from English help HTML bundled in installed ZAP add-ons.\n"
        )
        out.write(
            "  - ZAP alert instances are findings; this file is the source rule catalog.\n"
        )
        write_scalar_map(out, "addon_counts", addon_counts)
        out.write("rules:\n")
        for rule in rules:
            out.write(f"  - atomic_id: {yaml_string(rule['atomic_id'])}\n")
            out.write(f"    plugin_id: {yaml_string(rule['plugin_id'])}\n")
            out.write(f"    title: {yaml_string(rule['title'])}\n")
            out.write(f"    severity: {yaml_string(rule['severity'])}\n")
            out.write(f"    mode: {rule['mode']}\n")
            out.write(f"    addon: {yaml_string(rule['addon'])}\n")
            out.write(f"    source_path: {yaml_string(rule['source_path'])}\n")
    print(f"wrote {output} ({len(rules)} ZAP rules)")


def ast_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append("{expr}")
        return "".join(parts)
    return None


def ast_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = ast_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Constant):
        return str(node.value)
    return None


def class_bases(node: ast.ClassDef) -> list[str]:
    return [name for base in node.bases if (name := ast_name(base))]


def class_constant_attrs(node: ast.ClassDef) -> dict[str, object]:
    attrs: dict[str, object] = {}
    for stmt in node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            continue
        target = stmt.targets[0].id
        if isinstance(stmt.value, ast.Constant):
            attrs[target] = stmt.value.value
    return attrs


def find_init(node: ast.ClassDef) -> ast.FunctionDef | None:
    for stmt in node.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "__init__":
            return stmt
    return None


def internetnl_super_kwargs(init: ast.FunctionDef | None) -> dict[str, str]:
    if init is None:
        return {}
    for call in ast.walk(init):
        if not isinstance(call, ast.Call):
            continue
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "__init__":
            continue
        data: dict[str, str] = {}
        for keyword in call.keywords:
            if keyword.arg is None:
                continue
            value = ast_string(keyword.value) or ast_name(keyword.value)
            if value is not None:
                data[keyword.arg] = value
        return data
    return {}


def internetnl_category_subtests(init: ast.FunctionDef | None) -> list[str]:
    if init is None:
        return []
    subtests: list[str] = []
    for stmt in init.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "subtests" for target in stmt.targets):
            continue
        if isinstance(stmt.value, ast.List):
            for element in stmt.value.elts:
                name = ast_name(element)
                if name:
                    subtests.append(name)
    return subtests


def internetnl_scoring_constants() -> dict[str, str]:
    tree = ast.parse(INTERNETNL_SCORING.read_text(errors="ignore"))
    constants: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name):
            continue
        target = node.targets[0].id
        value = ast_name(node.value)
        if value:
            constants[target] = value

    def resolve(value: str, seen: set[str] | None = None) -> str:
        seen = seen or set()
        key = value.split(".")[-1]
        if key in seen:
            return value
        if key not in constants:
            return value
        seen.add(key)
        return resolve(constants[key], seen)

    return {key: resolve(value) for key, value in constants.items()}


def internetnl_status_severity(worst_status: str | None, constants: dict[str, str]) -> str:
    if not worst_status:
        return "info"
    status = constants.get(worst_status.split(".")[-1], worst_status).lower()
    if "fail" in status:
        return "medium"
    if "notice" in status:
        return "low"
    if "info" in status:
        return "info"
    return "info"


def internetnl_title(identifier: str) -> str:
    return identifier.replace("_", " ").replace("-", " ").strip().capitalize()


def extract_internetnl_subtests() -> list[dict[str, object]]:
    tree = ast.parse(INTERNETNL_CATEGORIES.read_text(errors="ignore"))
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    attrs = {name: class_constant_attrs(node) for name, node in classes.items()}
    scoring_constants = internetnl_scoring_constants()

    categories: dict[str, list[str]] = {}
    for name, node in classes.items():
        if "Category" not in class_bases(node):
            continue
        init = find_init(node)
        category_name = name
        if init and init.args.defaults:
            default_name = ast_string(init.args.defaults[-1])
            if default_name:
                category_name = default_name
        categories[category_name] = internetnl_category_subtests(init)

    subtest_categories: dict[str, list[str]] = collections.defaultdict(list)
    for category, subtests in categories.items():
        for subtest in subtests:
            subtest_categories[subtest].append(category)

    rows: dict[str, dict[str, object]] = {}
    for class_name, node in classes.items():
        bases = class_bases(node)
        class_attrs = attrs[class_name]
        init_kwargs = internetnl_super_kwargs(find_init(node))

        source_name = init_kwargs.get("name")
        if not source_name and isinstance(class_attrs.get("_test_name"), str):
            source_name = str(class_attrs["_test_name"])
        if not source_name:
            continue

        # Keep only concrete subtests that are actually wired into active
        # Internet.nl categories. The source tree also contains abstract bases
        # and disabled tests.
        if class_name not in subtest_categories:
            continue

        worst_status = init_kwargs.get("worst_status")
        full_score = init_kwargs.get("full_score")
        model_score_field = init_kwargs.get("model_score_field")
        label = init_kwargs.get("label")
        explanation = init_kwargs.get("explanation")
        categories_for_subtest = subtest_categories.get(class_name, [])
        atomic_prefixes = categories_for_subtest or ["internetnl"]
        for category in atomic_prefixes:
            atomic_id = f"internetnl.{category}.{source_name}".replace("_", "-")
            rows[atomic_id] = {
                "atomic_id": atomic_id,
                "source_subtest_id": source_name,
                "class_name": class_name,
                "title": internetnl_title(source_name),
                "category": category,
                "severity": internetnl_status_severity(worst_status, scoring_constants),
                "mode": "safe",
                "worst_status": worst_status or "",
                "resolved_worst_status": scoring_constants.get(
                    (worst_status or "").split(".")[-1],
                    worst_status or "",
                ),
                "full_score": full_score or "",
                "model_score_field": model_score_field or "",
                "label_key": label or "",
                "explanation_key": explanation or "",
            }
    return [rows[key] for key in sorted(rows)]


def write_internetnl_index() -> None:
    rows = extract_internetnl_subtests()
    category_counts = collections.Counter(str(row["category"]) for row in rows)
    output = PROJECT_ROOT / "catalog/generated/internetnl-subtest-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.internetnl-subtest-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"subtests_indexed: {len(rows)}\n")
        out.write("notes:\n")
        out.write(
            "  - Source-specific atomic IDs use the pattern internetnl.<category>.<subtest-id>.\n"
        )
        out.write(
            "  - Subtests were extracted statically from checks/categories.py in the open-source Internet.nl tree.\n"
        )
        out.write(
            "  - Internet.nl runs a multi-service stack; this index documents its source-level subtest model.\n"
        )
        write_scalar_map(out, "category_counts", category_counts)
        out.write("subtests:\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    source_subtest_id: {yaml_string(row['source_subtest_id'])}\n")
            out.write(f"    class_name: {yaml_string(row['class_name'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
            out.write(f"    category: {yaml_string(row['category'])}\n")
            out.write(f"    severity: {yaml_string(row['severity'])}\n")
            out.write(f"    mode: {row['mode']}\n")
            out.write(f"    worst_status: {yaml_string(row['worst_status'])}\n")
            out.write(
                f"    resolved_worst_status: {yaml_string(row['resolved_worst_status'])}\n"
            )
            out.write(f"    full_score: {yaml_string(row['full_score'])}\n")
            out.write(f"    model_score_field: {yaml_string(row['model_score_field'])}\n")
            out.write(f"    label_key: {yaml_string(row['label_key'])}\n")
            out.write(f"    explanation_key: {yaml_string(row['explanation_key'])}\n")
    print(f"wrote {output} ({len(rows)} Internet.nl subtests)")


def write_greenbone_index() -> None:
    nasl_count = len(greenbone_nasl_paths())
    output = PROJECT_ROOT / "catalog/generated/greenbone-feed-capability-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    feed_streams = [
        ("nvt", "NASL vulnerability tests", "community_free", "greenbone.nvt.<oid>"),
        ("notus", "Notus package vulnerability data", "community_free", "greenbone.notus.<advisory-or-cve>"),
        ("scap", "SCAP/CVE/CPE data", "community_free", "greenbone.scap.<cve-or-cpe>"),
        ("cert", "CERT-Bund and DFN-CERT advisory data", "community_free", "greenbone.cert.<advisory-id>"),
        ("gvmd-data", "GVMD data objects", "community_free", "greenbone.data-object.<id>"),
        ("scan-config", "Scan configuration definitions", "community_free", "greenbone.scan-config.<id>"),
        ("port-list", "Port list definitions", "community_free", "greenbone.port-list.<id>"),
        ("report-format", "Report format definitions", "community_free", "greenbone.report-format.<id>"),
        ("enterprise-feed", "Greenbone Enterprise Feed", "paid", "greenbone.enterprise.<id>"),
    ]
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.greenbone-feed-capability-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"greenbone_feed_sync_available: {'true' if shutil.which('greenbone-feed-sync') else 'false'}\n")
        out.write(f"gvm_cli_available: {'true' if shutil.which('gvm-cli') else 'false'}\n")
        out.write(f"rsync_available: {'true' if shutil.which('rsync') else 'false'}\n")
        out.write(f"local_nasl_files_observed: {nasl_count}\n")
        out.write("notes:\n")
        if nasl_count:
            out.write(
                "  - Local NASL/NVT feed data was observed and can be indexed into greenbone.nvt.<oid> source checks.\n"
            )
        else:
            out.write(
                "  - No local NVT OID index was generated because the inspected tools image does not contain synced Greenbone feed data.\n"
            )
        out.write(
            "  - Community feed streams are open-source/free to run after feed sync; Enterprise feed requires a paid key and is marked paid.\n"
        )
        out.write(
            "  - Source-specific NVT atomic IDs should use greenbone.nvt.<oid> once NASL metadata is available.\n"
        )
        out.write("feed_streams:\n")
        for stream, title, access, pattern in feed_streams:
            out.write(f"  - stream: {yaml_string(stream)}\n")
            out.write(f"    title: {yaml_string(title)}\n")
            out.write(f"    access: {yaml_string(access)}\n")
            out.write(f"    atomic_id_pattern: {yaml_string(pattern)}\n")
    print(f"wrote {output} (Greenbone feed data present: {nasl_count} NASL files)")


def greenbone_nasl_paths() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    env_dirs = [
        pathlib.Path(item)
        for item in os.environ.get("GREENBONE_NASL_DIRS", "").split(os.pathsep)
        if item
    ]
    for base in (*env_dirs, pathlib.Path("/var/lib"), pathlib.Path("/opt")):
        if base.exists():
            paths.extend(base.rglob("*.nasl"))
    return sorted(paths)


def env_paths(name: str, defaults: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    configured = [
        pathlib.Path(item)
        for item in os.environ.get(name, "").split(os.pathsep)
        if item
    ]
    return [*configured, *defaults]


def greenbone_notus_roots() -> list[pathlib.Path]:
    return env_paths(
        "GREENBONE_NOTUS_DIRS",
        [pathlib.Path("/var/lib/notus"), pathlib.Path("/opt/notus")],
    )


def greenbone_notus_files(subdir: str) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for base in greenbone_notus_roots():
        directory = base / subdir
        if directory.exists():
            paths.extend(path for path in directory.glob("*.notus") if path.is_file())
    return sorted(paths)


def greenbone_cert_roots() -> list[pathlib.Path]:
    return env_paths(
        "GREENBONE_CERT_DIRS",
        [pathlib.Path("/var/lib/gvm/cert-data"), pathlib.Path("/opt/gvm/cert-data")],
    )


def greenbone_cert_files() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for base in greenbone_cert_roots():
        if base.exists():
            paths.extend(
                path
                for path in base.glob("*.xml")
                if path.is_file() and path.name != "feed.xml"
            )
    return sorted(paths)


def greenbone_gvmd_roots() -> list[pathlib.Path]:
    return env_paths(
        "GREENBONE_GVMD_DIRS",
        [
            pathlib.Path("/var/lib/gvm/data-objects/gvmd"),
            pathlib.Path("/opt/gvm/data-objects/gvmd"),
        ],
    )


def greenbone_gvmd_files(subdir: str) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for base in greenbone_gvmd_roots():
        directory = base / subdir
        if directory.exists():
            paths.extend(path for path in directory.glob("*.xml") if path.is_file())
    return sorted(paths)


def greenbone_scap_roots() -> list[pathlib.Path]:
    return env_paths(
        "GREENBONE_SCAP_DIRS",
        [pathlib.Path("/var/lib/gvm/scap-data"), pathlib.Path("/opt/gvm/scap-data")],
    )


def greenbone_scap_cve_files() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for base in greenbone_scap_roots():
        if base.exists():
            paths.extend(path for path in base.glob("nvdcve-2.0-*.json.gz") if path.is_file())
    return sorted(paths)


def severity_from_cvss(value: str) -> str:
    try:
        score = float(value)
    except ValueError:
        return "info"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def first_text(element: ET.Element, name: str) -> str:
    child = element.find(name)
    if child is None or child.text is None:
        return ""
    return " ".join(child.text.split())


def all_texts(element: ET.Element, name: str) -> list[str]:
    return [
        " ".join(child.text.split())
        for child in element.findall(name)
        if child.text and child.text.strip()
    ]


def namespaced_child_text(element: ET.Element, namespace: str, name: str) -> str:
    return first_text(element, f"{{{namespace}}}{name}")


def source_id_fragment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value.strip()).strip("-")


def truncate_text(value: str, limit: int = 240) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def cvss_vector_family(value: str) -> str:
    value = value.strip()
    if value.startswith("CVSS:4."):
        return "cvss_v4"
    if value.startswith("CVSS:3."):
        return "cvss_v3"
    if value:
        return "cvss_v2"
    return ""


def first_regex(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.S)
    return match.group(1).strip() if match else ""


def greenbone_list_values(function_name: str, text: str) -> list[str]:
    match = re.search(function_name + r"\((.*?)\);", text, re.S)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def parse_greenbone_nasl(path: pathlib.Path) -> dict[str, object] | None:
    text = path.read_text(errors="ignore")
    oid = first_regex(r'script_oid\("([^"]+)"\);', text)
    name = first_regex(r'script_name\("((?:\\"|[^"])*)"\);', text).replace('\\"', '"')
    if not oid or not name:
        return None
    tags = {
        key: value.replace('\\"', '"')
        for key, value in re.findall(
            r'script_tag\(name:\s*"([^"]+)",\s*value:\s*"((?:\\"|[^"])*)"\);',
            text,
            re.S,
        )
    }
    return {
        "atomic_id": f"greenbone.nvt.{oid}",
        "nvt_oid": oid,
        "title": name,
        "family": first_regex(r'script_family\("([^"]+)"\);', text),
        "severity": severity_from_cvss(tags.get("cvss_base", "")),
        "cvss_base": tags.get("cvss_base", ""),
        "qod_type": tags.get("qod_type", ""),
        "qod_value": tags.get("qod", ""),
        "cves": greenbone_list_values("script_cve_id", text),
        "source_path": str(path),
    }


def write_greenbone_nvt_index() -> int:
    nasl_paths = greenbone_nasl_paths()
    nvts = [item for path in nasl_paths if (item := parse_greenbone_nasl(path))]
    output = PROJECT_ROOT / "catalog/generated/greenbone-nvt-index.yaml.gz"
    with open_output(output) as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.greenbone-nvt-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"nasl_files_observed: {len(nasl_paths)}\n")
        out.write(f"nvts_indexed: {len(nvts)}\n")
        out.write("notes:\n")
        if nvts:
            out.write("  - Source-specific atomic IDs use the pattern greenbone.nvt.<oid>.\n")
            out.write("  - NVT metadata was extracted from local NASL feed files.\n")
        else:
            out.write("  - No NVT OID entries were indexed because no synced NASL feed files were present in the inspected tools image.\n")
            out.write("  - Run Greenbone Community Feed sync in a full Greenbone stack, then regenerate this catalog to create greenbone.nvt.<oid> entries.\n")
        out.write("nvts:\n")
        if not nvts:
            out.write("  []\n")
        for item in nvts:
            out.write(f"  - atomic_id: {yaml_string(item['atomic_id'])}\n")
            out.write(f"    nvt_oid: {yaml_string(item['nvt_oid'])}\n")
            out.write(f"    title: {yaml_string(item['title'])}\n")
            out.write(f"    family: {yaml_string(item['family'])}\n")
            out.write(f"    severity: {yaml_string(item['severity'])}\n")
            out.write(f"    cvss_base: {yaml_string(item['cvss_base'])}\n")
            out.write(f"    qod_type: {yaml_string(item['qod_type'])}\n")
            out.write(f"    qod_value: {yaml_string(item['qod_value'])}\n")
            if item["cves"]:
                out.write("    cves:\n")
                for cve in item["cves"]:
                    out.write(f"      - {yaml_string(cve)}\n")
            else:
                out.write("    cves: []\n")
            out.write(f"    source_path: {yaml_string(item['source_path'])}\n")
    print(f"wrote {output} ({len(nvts)} Greenbone NVTs)")
    return len(nvts)


def greenbone_notus_product_refs() -> dict[str, dict[str, object]]:
    refs: dict[str, dict[str, object]] = {}
    for path in greenbone_notus_files("products"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        product_name = data.get("product_name") or path.stem
        package_type = data.get("package_type", "")
        for advisory in data.get("advisories", []):
            oid = advisory.get("oid")
            if not oid:
                continue
            item = refs.setdefault(
                oid,
                {
                    "products": set(),
                    "package_types": set(),
                    "fixed_package_count": 0,
                },
            )
            item["products"].add(str(product_name))
            if package_type:
                item["package_types"].add(str(package_type))
            item["fixed_package_count"] += len(advisory.get("fixed_packages", []))
    return refs


def parse_greenbone_notus_advisories() -> list[dict[str, object]]:
    product_refs = greenbone_notus_product_refs()
    rows: list[dict[str, object]] = []
    for path in greenbone_notus_files("advisories"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        family = data.get("family", "")
        for advisory in data.get("advisories", []):
            oid = advisory.get("oid")
            title = advisory.get("title")
            if not oid or not title:
                continue
            severity = advisory.get("severity", {})
            cvss_v3 = severity.get("cvss_v3", "") if isinstance(severity, dict) else ""
            cvss_v2 = severity.get("cvss_v2", "") if isinstance(severity, dict) else ""
            vector = cvss_v3 or cvss_v2
            refs = product_refs.get(
                oid,
                {"products": set(), "package_types": set(), "fixed_package_count": 0},
            )
            rows.append(
                {
                    "atomic_id": f"greenbone.notus.{oid}",
                    "notus_oid": oid,
                    "title": title,
                    "family": family,
                    "advisory_id": advisory.get("advisory_id", ""),
                    "advisory_xref": advisory.get("advisory_xref", ""),
                    "severity": "info",
                    "cvss_vector_family": cvss_vector_family(vector),
                    "cvss_vector": vector,
                    "qod_type": advisory.get("qod_type", ""),
                    "cves": advisory.get("cves", []),
                    "cisa_kev": bool(advisory.get("cisa_kev")),
                    "product_ref_count": len(refs["products"]),
                    "package_types": sorted(refs["package_types"]),
                    "fixed_package_count": refs["fixed_package_count"],
                    "source_path": str(path),
                }
            )
    return sorted(rows, key=lambda row: str(row["atomic_id"]))


def write_greenbone_notus_index() -> int:
    rows = parse_greenbone_notus_advisories()
    output = PROJECT_ROOT / "catalog/generated/greenbone-notus-advisory-index.yaml.gz"
    with open_output(output) as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.greenbone-notus-advisory-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"advisories_indexed: {len(rows)}\n")
        out.write("notes:\n")
        if rows:
            out.write("  - Source-specific atomic IDs use the pattern greenbone.notus.<oid>.\n")
            out.write("  - Advisory metadata was extracted from synced Greenbone Notus feed files.\n")
            out.write("  - Product and fixed-package references are aggregated evidence, not separate atomic checks.\n")
        else:
            out.write("  - No Notus advisories were indexed because no synced Notus feed files were present.\n")
        out.write("advisories:\n")
        if not rows:
            out.write("  []\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    notus_oid: {yaml_string(row['notus_oid'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
            out.write(f"    family: {yaml_string(row['family'])}\n")
            out.write(f"    advisory_id: {yaml_string(row['advisory_id'])}\n")
            out.write(f"    advisory_xref: {yaml_string(row['advisory_xref'])}\n")
            out.write(f"    severity: {yaml_string(row['severity'])}\n")
            out.write(f"    cvss_vector_family: {yaml_string(row['cvss_vector_family'])}\n")
            out.write(f"    cvss_vector: {yaml_string(row['cvss_vector'])}\n")
            out.write(f"    qod_type: {yaml_string(row['qod_type'])}\n")
            out.write(f"    cisa_kev: {'true' if row['cisa_kev'] else 'false'}\n")
            out.write(f"    product_ref_count: {row['product_ref_count']}\n")
            out.write("    package_types:\n")
            if row["package_types"]:
                for package_type in row["package_types"]:
                    out.write(f"      - {yaml_string(package_type)}\n")
            else:
                out.write("      []\n")
            out.write(f"    fixed_package_count: {row['fixed_package_count']}\n")
            if row["cves"]:
                out.write("    cves:\n")
                for cve in row["cves"]:
                    out.write(f"      - {yaml_string(cve)}\n")
            else:
                out.write("    cves: []\n")
            out.write(f"    source_path: {yaml_string(row['source_path'])}\n")
    print(f"wrote {output} ({len(rows)} Greenbone Notus advisories)")
    return len(rows)


def parse_greenbone_cert_bundle(root: ET.Element, path: pathlib.Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for advisory in root.findall("Advisory"):
        ref_num = first_text(advisory, "Ref_Num")
        title = first_text(advisory, "Title")
        if not ref_num or not title:
            continue
        score = first_text(advisory, "AggregatedCVSSScoreSet/ScoreSet/BaseScore")
        rows.append(
            {
                "atomic_id": f"greenbone.cert.{source_id_fragment(ref_num)}",
                "advisory_id": ref_num,
                "title": title,
                "feed_family": "cert-bund",
                "severity": severity_from_cvss(score),
                "risk": first_text(advisory, "Risk"),
                "cvss_base": score,
                "remote_attack": first_text(advisory, "RemoteAttack"),
                "reference_url": first_text(advisory, "Reference_URL"),
                "cves": all_texts(advisory.find("CVEList") or ET.Element("empty"), "CVE"),
                "source_path": str(path),
            }
        )
    return rows


def parse_greenbone_dfn_cert(root: ET.Element, path: pathlib.Path) -> list[dict[str, object]]:
    atom = "http://www.w3.org/2005/Atom"
    dfncert = "http://www.dfn-cert.de/dfncert.dtd"
    rows: list[dict[str, object]] = []
    for entry in root.findall(f"{{{atom}}}entry"):
        ref_num = namespaced_child_text(entry, dfncert, "refnum")
        title = namespaced_child_text(entry, atom, "title")
        if not ref_num or not title:
            continue
        link = entry.find(f"{{{atom}}}link")
        rows.append(
            {
                "atomic_id": f"greenbone.cert.{source_id_fragment(ref_num)}",
                "advisory_id": ref_num,
                "title": title,
                "feed_family": "dfn-cert",
                "severity": "info",
                "risk": "",
                "cvss_base": "",
                "remote_attack": "",
                "reference_url": link.get("href", "") if link is not None else "",
                "cves": all_texts(entry, f"{{{dfncert}}}cve"),
                "source_path": str(path),
            }
        )
    return rows


def parse_greenbone_cert_advisories() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in greenbone_cert_files():
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            continue
        if root.tag == "Advisories":
            rows.extend(parse_greenbone_cert_bundle(root, path))
        elif root.tag == "{http://www.w3.org/2005/Atom}feed":
            rows.extend(parse_greenbone_dfn_cert(root, path))
    return sorted(rows, key=lambda row: str(row["atomic_id"]))


def write_greenbone_cert_index() -> int:
    rows = parse_greenbone_cert_advisories()
    output = PROJECT_ROOT / "catalog/generated/greenbone-cert-advisory-index.yaml.gz"
    with open_output(output) as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.greenbone-cert-advisory-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"advisories_indexed: {len(rows)}\n")
        out.write("notes:\n")
        if rows:
            out.write("  - Source-specific atomic IDs use the pattern greenbone.cert.<advisory-id>.\n")
            out.write("  - Advisory metadata was extracted from synced CERT-Bund and DFN-CERT feed files.\n")
        else:
            out.write("  - No CERT advisories were indexed because no synced CERT feed files were present.\n")
        out.write("advisories:\n")
        if not rows:
            out.write("  []\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    advisory_id: {yaml_string(row['advisory_id'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
            out.write(f"    feed_family: {yaml_string(row['feed_family'])}\n")
            out.write(f"    severity: {yaml_string(row['severity'])}\n")
            out.write(f"    risk: {yaml_string(row['risk'])}\n")
            out.write(f"    cvss_base: {yaml_string(row['cvss_base'])}\n")
            out.write(f"    remote_attack: {yaml_string(row['remote_attack'])}\n")
            out.write(f"    reference_url: {yaml_string(row['reference_url'])}\n")
            if row["cves"]:
                out.write("    cves:\n")
                for cve in row["cves"]:
                    out.write(f"      - {yaml_string(cve)}\n")
            else:
                out.write("    cves: []\n")
            out.write(f"    source_path: {yaml_string(row['source_path'])}\n")
    print(f"wrote {output} ({len(rows)} Greenbone CERT advisories)")
    return len(rows)


def parse_greenbone_gvmd_objects() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in greenbone_gvmd_files("scan-configs"):
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            continue
        object_id = root.get("id", "")
        name = first_text(root, "name")
        if not object_id or not name:
            continue
        rows.append(
            {
                "atomic_id": f"greenbone.scan-config.{object_id}",
                "object_id": object_id,
                "object_type": "scan-config",
                "title": name,
                "category": "scan_control",
                "usage_type": first_text(root, "usage_type"),
                "selector_count": len(root.findall("nvt_selectors/nvt_selector")),
                "preference_count": len(root.findall("preferences/preference")),
                "port_range_count": 0,
                "extension": "",
                "content_type": "",
                "source_path": str(path),
            }
        )
    for path in greenbone_gvmd_files("port-lists"):
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            continue
        object_id = root.get("id", "")
        name = first_text(root, "name")
        if not object_id or not name:
            continue
        rows.append(
            {
                "atomic_id": f"greenbone.port-list.{object_id}",
                "object_id": object_id,
                "object_type": "port-list",
                "title": name,
                "category": "scan_control",
                "usage_type": "",
                "selector_count": 0,
                "preference_count": 0,
                "port_range_count": len(root.findall("port_ranges/port_range")),
                "extension": "",
                "content_type": "",
                "source_path": str(path),
            }
        )
    for path in greenbone_gvmd_files("report-formats"):
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            continue
        object_id = root.get("id", "")
        name = first_text(root, "name")
        if not object_id or not name:
            continue
        rows.append(
            {
                "atomic_id": f"greenbone.report-format.{object_id}",
                "object_id": object_id,
                "object_type": "report-format",
                "title": name,
                "category": "reporting",
                "usage_type": first_text(root, "report_type"),
                "selector_count": 0,
                "preference_count": 0,
                "port_range_count": 0,
                "extension": first_text(root, "extension"),
                "content_type": first_text(root, "content_type"),
                "source_path": str(path),
            }
        )
    return sorted(rows, key=lambda row: str(row["atomic_id"]))


def write_greenbone_gvmd_data_index() -> int:
    rows = parse_greenbone_gvmd_objects()
    output = PROJECT_ROOT / "catalog/generated/greenbone-gvmd-data-object-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.greenbone-gvmd-data-object-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"objects_indexed: {len(rows)}\n")
        out.write("notes:\n")
        if rows:
            out.write("  - Source-specific atomic IDs use greenbone.scan-config.<uuid>, greenbone.port-list.<uuid> and greenbone.report-format.<uuid>.\n")
            out.write("  - Scan configs can represent scan policy/compliance capabilities; port lists and report formats are scan/report metadata.\n")
        else:
            out.write("  - No GVMD data objects were indexed because no synced GVMD data feed files were present.\n")
        out.write("objects:\n")
        if not rows:
            out.write("  []\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    object_id: {yaml_string(row['object_id'])}\n")
            out.write(f"    object_type: {yaml_string(row['object_type'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
            out.write(f"    category: {yaml_string(row['category'])}\n")
            out.write(f"    usage_type: {yaml_string(row['usage_type'])}\n")
            out.write(f"    selector_count: {row['selector_count']}\n")
            out.write(f"    preference_count: {row['preference_count']}\n")
            out.write(f"    port_range_count: {row['port_range_count']}\n")
            out.write(f"    extension: {yaml_string(row['extension'])}\n")
            out.write(f"    content_type: {yaml_string(row['content_type'])}\n")
            out.write(f"    source_path: {yaml_string(row['source_path'])}\n")
    print(f"wrote {output} ({len(rows)} Greenbone GVMD data objects)")
    return len(rows)


def english_description(cve: dict[str, object]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return truncate_text(str(item.get("value", "")))
    return ""


def cwe_values(cve: dict[str, object]) -> list[str]:
    values: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value and value not in {"NVD-CWE-noinfo", "NVD-CWE-Other"}:
                values.add(str(value))
    return sorted(values)


def count_cpe_matches(nodes: list[dict[str, object]]) -> int:
    total = 0
    for node in nodes:
        total += len(node.get("cpeMatch", []))
        total += count_cpe_matches(node.get("children", []))
    return total


def best_cvss(cve: dict[str, object]) -> dict[str, object]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key, [])
        if not candidates:
            continue
        primary = next((item for item in candidates if item.get("type") == "Primary"), candidates[0])
        data = primary.get("cvssData", {})
        score = data.get("baseScore", "")
        severity = data.get("baseSeverity", primary.get("baseSeverity", ""))
        return {
            "version": data.get("version", ""),
            "score": score,
            "severity": str(severity).lower() if severity else severity_from_cvss(str(score)),
            "vector": data.get("vectorString", ""),
        }
    return {"version": "", "score": "", "severity": "info", "vector": ""}


def parse_greenbone_scap_cves() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in greenbone_scap_cve_files():
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            cvss = best_cvss(cve)
            configurations = cve.get("configurations", [])
            rows.append(
                {
                    "atomic_id": f"greenbone.scap.{cve_id}",
                    "cve_id": cve_id,
                    "title": cve_id,
                    "description": english_description(cve),
                    "status": cve.get("vulnStatus", ""),
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "severity": cvss["severity"],
                    "cvss_version": cvss["version"],
                    "cvss_score": cvss["score"],
                    "cvss_vector": cvss["vector"],
                    "cwes": cwe_values(cve),
                    "reference_count": len(cve.get("references", [])),
                    "vulnerable_cpe_match_count": sum(
                        count_cpe_matches(config.get("nodes", []))
                        for config in configurations
                    ),
                    "source_path": str(path),
                }
            )
    return sorted(rows, key=lambda row: str(row["atomic_id"]))


def write_greenbone_scap_cve_index() -> int:
    rows = parse_greenbone_scap_cves()
    output = PROJECT_ROOT / "catalog/generated/greenbone-scap-cve-index.yaml.gz"
    with open_output(output) as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.greenbone-scap-cve-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"cves_indexed: {len(rows)}\n")
        out.write("notes:\n")
        if rows:
            out.write("  - Source-specific atomic IDs use the pattern greenbone.scap.<cve-id>.\n")
            out.write("  - CVE metadata was extracted from synced Greenbone SCAP/NVD JSON feed files.\n")
            out.write("  - CPE matches are aggregated evidence counts, not separate atomic checks.\n")
        else:
            out.write("  - No SCAP CVEs were indexed because no synced SCAP CVE feed files were present.\n")
        out.write("cves:\n")
        if not rows:
            out.write("  []\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    cve_id: {yaml_string(row['cve_id'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
            out.write(f"    description: {yaml_string(row['description'])}\n")
            out.write(f"    status: {yaml_string(row['status'])}\n")
            out.write(f"    published: {yaml_string(row['published'])}\n")
            out.write(f"    last_modified: {yaml_string(row['last_modified'])}\n")
            out.write(f"    severity: {yaml_string(row['severity'])}\n")
            out.write(f"    cvss_version: {yaml_string(row['cvss_version'])}\n")
            out.write(f"    cvss_score: {yaml_string(row['cvss_score'])}\n")
            out.write(f"    cvss_vector: {yaml_string(row['cvss_vector'])}\n")
            if row["cwes"]:
                out.write("    cwes:\n")
                for cwe in row["cwes"]:
                    out.write(f"      - {yaml_string(cwe)}\n")
            else:
                out.write("    cwes: []\n")
            out.write(f"    reference_count: {row['reference_count']}\n")
            out.write(f"    vulnerable_cpe_match_count: {row['vulnerable_cpe_match_count']}\n")
            out.write(f"    source_path: {yaml_string(row['source_path'])}\n")
    print(f"wrote {output} ({len(rows)} Greenbone SCAP CVEs)")
    return len(rows)


PROJECTDISCOVERY_CAPABILITIES = [
    ("subfinder.passive-subdomain-discovery", "Passive subdomain discovery", "subfinder", "attack_surface", "safe", "info", ["domain", "hostname", "source"]),
    ("subfinder.source-selection", "Passive source include/exclude selection", "subfinder", "scan_control", "safe", "info", ["source_name", "included", "excluded"]),
    ("subfinder.recursive-source-discovery", "Recursive-capable source discovery", "subfinder", "attack_surface", "safe", "info", ["domain", "hostname", "recursive_source"]),
    ("subfinder.all-sources-discovery", "All configured passive sources discovery", "subfinder", "attack_surface", "safe", "info", ["domain", "hostname", "source"]),
    ("subfinder.json-source-attribution", "JSONL source attribution for discovered names", "subfinder", "evidence_quality", "safe", "info", ["hostname", "sources"]),
    ("subfinder.active-resolution", "Active resolution of discovered subdomains", "subfinder", "attack_surface", "aggressive", "info", ["hostname", "ip"]),
    ("subfinder.source-statistics", "Passive source statistics", "subfinder", "evidence_quality", "safe", "info", ["source_name", "count"]),
    ("httpx.status-code", "HTTP status code probe", "httpx", "web_inventory", "aggressive", "info", ["url", "status_code"]),
    ("httpx.content-length", "HTTP content length probe", "httpx", "web_inventory", "aggressive", "info", ["url", "content_length"]),
    ("httpx.content-type", "HTTP content type probe", "httpx", "web_inventory", "aggressive", "info", ["url", "content_type"]),
    ("httpx.redirect-location", "HTTP redirect location probe", "httpx", "quality", "aggressive", "info", ["url", "location"]),
    ("httpx.favicon-hash", "Favicon hash fingerprint", "httpx", "fingerprint", "aggressive", "info", ["url", "favicon_hash"]),
    ("httpx.response-hash", "HTTP response body hash fingerprint", "httpx", "fingerprint", "aggressive", "info", ["url", "hash_type", "hash"]),
    ("httpx.jarm", "JARM TLS fingerprint", "httpx", "fingerprint", "aggressive", "info", ["host", "port", "jarm"]),
    ("httpx.response-time", "HTTP response time measurement", "httpx", "performance", "aggressive", "info", ["url", "response_time"]),
    ("httpx.title", "HTML title extraction", "httpx", "web_inventory", "aggressive", "info", ["url", "title"]),
    ("httpx.web-server", "HTTP server header extraction", "httpx", "fingerprint", "aggressive", "low", ["url", "server"]),
    ("httpx.technology-detect", "Technology fingerprint detection", "httpx", "fingerprint", "aggressive", "info", ["url", "technology"]),
    ("httpx.cpe-detect", "CPE technology mapping", "httpx", "fingerprint", "aggressive", "medium", ["url", "cpe"]),
    ("httpx.wordpress-detect", "WordPress component detection", "httpx", "fingerprint", "aggressive", "medium", ["url", "component", "version"]),
    ("httpx.websocket-detect", "WebSocket service detection", "httpx", "protocol_inventory", "aggressive", "info", ["url", "websocket"]),
    ("httpx.ip-cname", "Resolved IP and CNAME extraction", "httpx", "attack_surface", "aggressive", "info", ["host", "ip", "cname"]),
    ("httpx.extract-fqdn", "FQDN extraction from response", "httpx", "exposure", "aggressive", "low", ["url", "fqdn"]),
    ("httpx.asn", "ASN enrichment", "httpx", "attack_surface", "aggressive", "info", ["ip", "asn", "organization"]),
    ("httpx.cdn-waf", "CDN/WAF detection", "httpx", "attack_surface", "aggressive", "info", ["host", "provider"]),
    ("httpx.screenshot", "Web page screenshot capture", "httpx", "quality", "aggressive", "info", ["url", "screenshot_file"]),
    ("httpx.tls-grab", "TLS metadata grab", "httpx", "tls", "aggressive", "info", ["host", "port", "tls"]),
    ("httpx.csp-probe", "CSP header probe", "httpx", "http_security", "aggressive", "low", ["url", "csp"]),
    ("httpx.http2", "HTTP/2 support probe", "httpx", "protocol_inventory", "aggressive", "info", ["url", "http2"]),
    ("httpx.pipeline", "HTTP/1.1 pipeline support probe", "httpx", "protocol_inventory", "aggressive", "low", ["url", "pipeline"]),
    ("httpx.vhost", "Virtual host response probe", "httpx", "attack_surface", "aggressive", "info", ["host", "vhost", "status_code"]),
    ("httpx.page-type-login", "Login page classification", "httpx", "attack_surface", "aggressive", "info", ["url", "page_type"]),
    ("httpx.page-type-captcha", "CAPTCHA or bot protection classification", "httpx", "quality", "aggressive", "info", ["url", "page_type"]),
    ("httpx.page-type-parked", "Parked page classification", "httpx", "quality", "aggressive", "low", ["url", "page_type"]),
    ("naabu.open-ports", "Open TCP port inventory", "naabu", "attack_surface", "aggressive", "medium", ["host", "ip", "port"]),
    ("naabu.top-ports", "Top port-set scanning", "naabu", "attack_surface", "aggressive", "medium", ["host", "port"]),
    ("naabu.passive-internetdb", "Passive Shodan InternetDB open port evidence", "naabu", "external_public", "safe", "medium", ["host", "port", "source"]),
    ("naabu.host-discovery", "Host discovery probing", "naabu", "attack_surface", "aggressive", "info", ["host", "ip", "method"]),
    ("naabu.service-discovery", "Service discovery probe", "naabu", "fingerprint", "aggressive", "medium", ["host", "port", "service"]),
    ("naabu.service-version", "Service version probe", "naabu", "fingerprint", "aggressive", "medium", ["host", "port", "product", "version"]),
    ("naabu.cdn-detection", "CDN/WAF detection for scan scope", "naabu", "attack_surface", "aggressive", "info", ["host", "provider"]),
    ("naabu.reverse-ptr", "Reverse PTR lookup", "naabu", "attack_surface", "aggressive", "info", ["ip", "ptr_name"]),
    ("naabu.ip-version-scope", "IPv4/IPv6 scan scope selection", "naabu", "scan_control", "aggressive", "info", ["host", "ip_version"]),
]


AMASS_CAPABILITIES = [
    ("enum.passive-enumeration", "Passive domain enumeration", "enum", "attack_surface", "safe", "info", ["domain", "hostname", "source"]),
    ("enum.active-certificate-grab", "Active certificate name grabbing", "enum", "attack_surface", "aggressive", "info", ["host", "certificate_name"]),
    ("enum.zone-transfer-attempt", "DNS zone transfer attempt", "enum", "dns", "aggressive", "high", ["domain", "nameserver", "axfr_result"]),
    ("enum.altered-name-generation", "Altered-name generation", "enum", "attack_surface", "aggressive", "info", ["candidate_hostname", "generation_method"]),
    ("enum.bruteforce", "DNS brute-force enumeration", "enum", "attack_surface", "aggressive", "info", ["candidate_hostname", "resolved"]),
    ("enum.recursive-bruteforce", "Recursive DNS brute-force enumeration", "enum", "attack_surface", "aggressive", "info", ["hostname", "depth"]),
    ("enum.asn-scope", "ASN-based scope input", "enum", "attack_surface", "aggressive", "info", ["asn", "related_asset"]),
    ("enum.cidr-scope", "CIDR-based scope input", "enum", "attack_surface", "aggressive", "info", ["cidr", "related_asset"]),
    ("enum.address-scope", "Address/range-based scope input", "enum", "attack_surface", "aggressive", "info", ["ip_range", "related_asset"]),
    ("enum.source-include-exclude", "Data source include/exclude control", "enum", "scan_control", "safe", "info", ["source_name", "included", "excluded"]),
    ("enum.resolver-selection", "Trusted/untrusted resolver selection", "enum", "scan_control", "aggressive", "info", ["resolver", "trust_level"]),
    ("subs.names", "Discovered subdomain names output", "subs", "attack_surface", "safe", "info", ["domain", "hostname"]),
    ("subs.addresses", "Discovered subdomain address output", "subs", "attack_surface", "safe", "info", ["hostname", "ip"]),
    ("subs.asn-summary", "ASN summary output", "subs", "attack_surface", "safe", "info", ["asn", "organization", "count"]),
    ("assoc.relationship-walk", "Open Asset Model relationship walk", "assoc", "attack_surface", "safe", "info", ["source_asset", "relationship", "target_asset"]),
    ("track.new-assets", "New asset tracking across enumerations", "track", "attack_surface", "safe", "info", ["asset", "first_seen"]),
    ("viz.asset-graph", "Asset graph visualization", "viz", "attack_surface", "safe", "info", ["graph_file", "asset_count", "edge_count"]),
]


SUBFINDER_PROVIDERS = """
alienvault|required_key
anubis|none
bevigil|required_key
bufferover|required_key
builtwith|required_key
c99|required_key
censys|required_key
certspotter|required_key
chaos|required_key
chinaz|required_key
commoncrawl|none
crtsh|none
digitalyama|required_key
digitorus|none
dnsdb|required_key
dnsdumpster|required_key
dnsrepo|required_key
domainsproject|required_key
driftnet|required_key
fofa|required_key
fullhunt|required_key
github|required_key
hackertarget|optional_key
hudsonrock|none
intelx|required_key
leakix|required_key
merklemap|required_key
netlas|required_key
onyphe|required_key
profundis|required_key
pugrecon|required_key
quake|required_key
rapiddns|none
reconeer|optional_key
redhuntlabs|required_key
robtex|required_key
rsecloud|required_key
securitytrails|required_key
shodan|required_key
sitedossier|none
thc|none
threatbook|required_key
threatcrowd|none
urlscan|required_key
virustotal|required_key
waybackarchive|required_key
whoisxmlapi|required_key
windvane|required_key
zoomeyeapi|required_key
submd|optional_key
""".strip().splitlines()


AMASS_PROVIDER_SCRIPTS = """
alt|alterations
api|360passivedns
api|ahrefs
api|alienvault
api|anubisdb
api|asnlookup
api|bevigil
api|bgptools
api|bgpview
api|bigdatacloud
api|binaryedge
api|bufferover
api|builtwith
api|c99
api|chaos
api|circl
api|deepinfo
api|detectify
api|dnsdb
api|dnslytics
api|dnsrepo
api|fofa
api|fullhunt
api|github
api|gitlab
api|grepapp
api|greynoise
api|hackertarget
api|hunter
api|intelx
api|ipdata
api|ipinfo
api|leakix
api|maltiverse
api|mnemonic
api|netlas
api|onyphe
api|passivetotal
api|pastebin
api|pentesttools
api|pulsedive
api|quake
api|searchcode
api|securitytrails
api|shodan
api|socradar
api|spamhaus
api|subdomaincenter
api|sublist3r
api|threatbook
api|threatminer
api|urlscan
api|virustotal
api|whoisxmlapi
api|yandex
api|zetalytics
api|zoomeye
archive|arquivo
archive|haw
archive|ukwebarchive
archive|wayback
brute|bruteforcing
cert|censys
cert|certcentral
cert|certspotter
cert|crtsh
cert|digitorus
cert|facebookct
crawl|active
crawl|commoncrawl
crawl|publicwww
dns|active
dns|srv
dns|sweep
misc|shadowserver
misc|teamcymru
scrape|abuseipdb
scrape|ask
scrape|askdns
scrape|baidu
scrape|bing
scrape|dnsdumpster
scrape|dnshistory
scrape|dnsspy
scrape|duckduckgo
scrape|gists
scrape|google
scrape|hackerone
scrape|hyperstat
scrape|pkey
scrape|rapiddns
scrape|riddler
scrape|searx
scrape|sitedossier
scrape|spyonweb
scrape|synapsint
scrape|yahoo
""".strip().splitlines()


def provider_access_from_key_requirement(key_requirement: str) -> str:
    if key_requirement == "none":
        return "free_public_no_key"
    if key_requirement == "optional_key":
        return "free_with_optional_key"
    return "credentials_required"


def amass_provider_access(category: str) -> str:
    if category in {"alt", "brute", "dns"}:
        return "open_source_free"
    if category == "api":
        return "credentials_required"
    return "free_public_no_key"


def write_provider_rows(out, rows: list[dict[str, str]]) -> None:
    out.write("providers:\n")
    for row in rows:
        out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
        out.write(f"    provider: {yaml_string(row['provider'])}\n")
        if row.get("category"):
            out.write(f"    category: {yaml_string(row['category'])}\n")
        if row.get("key_requirement"):
            out.write(f"    key_requirement: {yaml_string(row['key_requirement'])}\n")
        out.write(f"    access: {yaml_string(row['access'])}\n")
        out.write(f"    title: {yaml_string(row['title'])}\n")


def write_subfinder_provider_index() -> int:
    rows = []
    for line in SUBFINDER_PROVIDERS:
        name, key_requirement = line.split("|", 1)
        rows.append(
            {
                "atomic_id": f"subfinder.provider.{name}",
                "provider": name,
                "key_requirement": key_requirement,
                "access": provider_access_from_key_requirement(key_requirement),
                "title": f"Subfinder provider: {name}",
            }
        )
    key_counts = collections.Counter(row["key_requirement"] for row in rows)
    access_counts = collections.Counter(row["access"] for row in rows)
    output = PROJECT_ROOT / "catalog/generated/subfinder-provider-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.subfinder-provider-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        out.write("  - Source-specific atomic IDs use subfinder.provider.<name>.\n")
        out.write("  - Provider names and key markers are derived from subfinder -ls and upstream pkg/passive sources.\n")
        out.write(f"  - {yaml_string('* providers require keys/tokens; ~ providers optionally support keys for better results.')}\n")
        write_scalar_map(out, "key_requirement_counts", key_counts)
        write_scalar_map(out, "access_counts", access_counts)
        write_provider_rows(out, rows)
    print(f"wrote {output} ({len(rows)} Subfinder providers)")
    return len(rows)


def write_amass_provider_index() -> int:
    rows = []
    for line in AMASS_PROVIDER_SCRIPTS:
        category, name = line.split("|", 1)
        rows.append(
            {
                "atomic_id": f"amass.provider.{category}.{name}",
                "provider": name,
                "category": category,
                "access": amass_provider_access(category),
                "title": f"Amass {category} data source: {name}",
            }
        )
    category_counts = collections.Counter(row["category"] for row in rows)
    access_counts = collections.Counter(row["access"] for row in rows)
    output = PROJECT_ROOT / "catalog/generated/amass-provider-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.amass-provider-index\n")
        out.write("generated_from: 'https://github.com/owasp-amass/amass/tree/master/resources/scripts'\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        out.write("  - Source-specific atomic IDs use amass.provider.<script-category>.<script-name>.\n")
        out.write("  - Entries are derived from the open-source Amass resources/scripts ADS source tree.\n")
        out.write("  - API category scripts are marked credentials_required by default; exact provider plans can be refined in source-access-policy.\n")
        write_scalar_map(out, "category_counts", category_counts)
        write_scalar_map(out, "access_counts", access_counts)
        write_provider_rows(out, rows)
    print(f"wrote {output} ({len(rows)} Amass providers)")
    return len(rows)


def write_capability_rows(out, rows: list[tuple[str, str, str, str, str, str, list[str]]]) -> None:
    out.write("capabilities:\n")
    for identifier, title, tool_or_command, category, mode, severity, evidence in rows:
        out.write(f"  - atomic_id: {yaml_string(identifier)}\n")
        out.write(f"    title: {yaml_string(title)}\n")
        out.write(f"    source: {yaml_string(tool_or_command)}\n")
        out.write(f"    category: {yaml_string(category)}\n")
        out.write(f"    mode: {mode}\n")
        out.write(f"    severity: {severity}\n")
        out.write("    evidence_model:\n")
        for field in evidence:
            out.write(f"      - {yaml_string(field)}\n")


def write_projectdiscovery_index() -> None:
    rows = [
        (f"projectdiscovery.{identifier}", title, tool, category, mode, severity, evidence)
        for identifier, title, tool, category, mode, severity, evidence in PROJECTDISCOVERY_CAPABILITIES
    ]
    tool_counts = collections.Counter(tool for _, _, tool, _, _, _, _ in PROJECTDISCOVERY_CAPABILITIES)
    output = PROJECT_ROOT / "catalog/generated/projectdiscovery-capability-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.projectdiscovery-capability-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"capabilities_indexed: {len(rows)}\n")
        out.write("notes:\n")
        out.write(
            "  - These tools expose repeatable evidence capabilities rather than source rule IDs.\n"
        )
        out.write(
            "  - Capability IDs use projectdiscovery.<tool>.<capability> and should map to canonical Domain Score checks.\n"
        )
        out.write(
            "  - Runtime verification found the inspected image's httpx command currently resolves to Python HTTPX, so ProjectDiscovery httpx runtime output requires an image fix.\n"
        )
        write_scalar_map(out, "tool_counts", tool_counts)
        write_capability_rows(out, rows)
    print(f"wrote {output} ({len(rows)} ProjectDiscovery capabilities)")


def write_amass_index() -> None:
    rows = [
        (f"amass.{identifier}", title, command, category, mode, severity, evidence)
        for identifier, title, command, category, mode, severity, evidence in AMASS_CAPABILITIES
    ]
    command_counts = collections.Counter(command for _, _, command, _, _, _, _ in AMASS_CAPABILITIES)
    output = PROJECT_ROOT / "catalog/generated/amass-capability-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.amass-capability-index\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write(f"capabilities_indexed: {len(rows)}\n")
        out.write("notes:\n")
        out.write(
            "  - Amass exposes attack-surface mapping capabilities rather than fixed vulnerability rule IDs.\n"
        )
        out.write(
            "  - Capability IDs use amass.<command>.<capability> and runtime values remain findings.\n"
        )
        write_scalar_map(out, "command_counts", command_counts)
        write_capability_rows(out, rows)
    print(f"wrote {output} ({len(rows)} Amass capabilities)")


MOZILLA_OBSERVATORY_EXPECTATIONS = """
content-security-policy|csp-implemented-with-no-unsafe
content-security-policy|csp-implemented-with-no-unsafe-default-src-none
content-security-policy|csp-implemented-with-unsafe-inline-in-style-src-only
content-security-policy|csp-implemented-with-insecure-scheme-in-passive-content-only
content-security-policy|csp-implemented-with-unsafe-inline
content-security-policy|csp-implemented-with-unsafe-eval
content-security-policy|csp-implemented-with-insecure-scheme
content-security-policy|csp-header-invalid
content-security-policy|csp-not-implemented
content-security-policy|csp-not-implemented-but-reporting-enabled
content-security-policy|csp-implemented-but-duplicate-directives
subresource-integrity|sri-implemented-and-all-scripts-loaded-securely
subresource-integrity|sri-implemented-and-external-scripts-loaded-securely
subresource-integrity|sri-implemented-but-external-scripts-not-loaded-securely
subresource-integrity|sri-not-implemented-and-external-scripts-not-loaded-securely
subresource-integrity|sri-not-implemented-but-all-scripts-loaded-from-secure-origin
subresource-integrity|sri-not-implemented-but-external-scripts-loaded-securely
subresource-integrity|sri-not-implemented-but-no-scripts-loaded
subresource-integrity|sri-not-implemented-response-not-html
generic|html-not-parseable
strict-transport-security|hsts-header-invalid
strict-transport-security|hsts-implemented-max-age-at-least-six-months
strict-transport-security|hsts-implemented-max-age-less-than-six-months
strict-transport-security|hsts-invalid-cert
strict-transport-security|hsts-not-implemented-no-https
strict-transport-security|hsts-not-implemented
strict-transport-security|hsts-preloaded
cookies|cookies-anticsrf-without-samesite-flag
cookies|cookies-not-found
cookies|cookies-samesite-flag-invalid
cookies|cookies-secure-with-httponly-sessions-and-samesite
cookies|cookies-secure-with-httponly-sessions
cookies|cookies-session-without-httponly-flag
cookies|cookies-session-without-secure-flag-but-protected-by-hsts
cookies|cookies-session-without-secure-flag
cookies|cookies-without-secure-flag-but-protected-by-hsts
cookies|cookies-without-secure-flag
x-frame-options|x-frame-options-allow-from-origin
x-frame-options|x-frame-options-header-invalid
x-frame-options|x-frame-options-implemented-via-csp
x-frame-options|x-frame-options-not-implemented
x-frame-options|x-frame-options-sameorigin-or-deny
redirection|redirection-to-https
redirection|redirection-not-to-https
redirection|redirection-not-to-https-on-initial-redirection
redirection|redirection-missing
redirection|redirection-not-needed-no-http
redirection|redirection-off-host-from-http
redirection|redirection-invalid-cert
redirection|redirection-all-redirects-preloaded
referrer-policy|referrer-policy-private
referrer-policy|referrer-policy-unsafe
referrer-policy|referrer-policy-not-implemented
referrer-policy|referrer-policy-header-invalid
x-content-type-options|x-content-type-options-nosniff
x-content-type-options|x-content-type-options-not-implemented
x-content-type-options|x-content-type-options-header-invalid
cross-origin-resource-sharing|cross-origin-resource-sharing-not-implemented
cross-origin-resource-sharing|cross-origin-resource-sharing-implemented-with-public-access
cross-origin-resource-sharing|cross-origin-resource-sharing-implemented-with-restricted-access
cross-origin-resource-sharing|cross-origin-resource-sharing-implemented-with-universal-access
cross-origin-resource-policy|corp-not-implemented
cross-origin-resource-policy|corp-implemented-with-same-origin
cross-origin-resource-policy|corp-implemented-with-same-site
cross-origin-resource-policy|corp-implemented-with-cross-origin
cross-origin-resource-policy|corp-header-invalid
""".strip().splitlines()


def title_from_slug(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ").strip().capitalize()


def write_mozilla_observatory_index() -> int:
    rows = []
    for line in MOZILLA_OBSERVATORY_EXPECTATIONS:
        test_name, expectation = line.split("|", 1)
        rows.append(
            {
                "atomic_id": f"mozilla_observatory.{expectation}",
                "test": test_name,
                "expectation": expectation,
                "title": title_from_slug(expectation),
            }
        )
    output = PROJECT_ROOT / "catalog/generated/mozilla-observatory-expectation-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    test_counts = collections.Counter(row["test"] for row in rows)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.mozilla-observatory-expectation-index\n")
        out.write("generated_from: 'https://github.com/mdn/mdn-http-observatory'\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        out.write("  - Source-specific atomic IDs use mozilla_observatory.<expectation>.\n")
        out.write("  - Entries are derived from the open-source MDN HTTP Observatory analyzer tests and Expectation enum.\n")
        out.write("  - Runtime values are third-party scan findings; this file records the source result vocabulary.\n")
        write_scalar_map(out, "test_counts", test_counts)
        out.write("expectations:\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    test: {yaml_string(row['test'])}\n")
            out.write(f"    expectation: {yaml_string(row['expectation'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
    print(f"wrote {output} ({len(rows)} Mozilla Observatory expectations)")
    return len(rows)


SSL_LABS_FIELDS = """
endpoint.grade|Endpoint grade
endpoint.gradeTrustIgnored|Endpoint grade ignoring trust issues
endpoint.hasWarnings|Endpoint has grade-affecting warnings
endpoint.isExceptional|Endpoint exceptional configuration flag
endpoint_details.serverSignature|HTTP Server header value
endpoint_details.prefixDelegation|www-prefixed hostname reachability
endpoint_details.nonPrefixDelegation|apex/non-www hostname reachability
endpoint_details.vulnBeast|BEAST vulnerability signal
endpoint_details.renegSupport|TLS renegotiation support bits
endpoint_details.sessionResumption|TLS session resumption support
endpoint_details.compressionMethods|TLS compression support
endpoint_details.supportsNpn|NPN support
endpoint_details.supportsAlpn|ALPN support
endpoint_details.alpnProtocols|ALPN protocol list
endpoint_details.sessionTickets|TLS session ticket support
endpoint_details.ocspStapling|OCSP stapling deployment
endpoint_details.staplingRevocationStatus|Stapled OCSP revocation status
endpoint_details.sniRequired|SNI required signal
endpoint_details.httpStatusCode|Final HTTP status code
endpoint_details.supportsRc4|RC4 cipher support
endpoint_details.rc4WithModern|RC4 negotiated with modern clients
endpoint_details.rc4Only|Only RC4 suites supported
endpoint_details.forwardSecrecy|Forward secrecy support bits
endpoint_details.protocolIntolerance|TLS protocol intolerance bits
endpoint_details.miscIntolerance|TLS extension or handshake intolerance bits
endpoint_details.supportsCBC|CBC cipher support
endpoint_details.heartbleed|Heartbleed vulnerability signal
endpoint_details.heartbeat|TLS Heartbeat extension support
endpoint_details.openSslCcs|OpenSSL CCS injection test result
endpoint_details.openSSLLuckyMinus20|OpenSSL LuckyMinus20 test result
endpoint_details.ticketbleed|Ticketbleed vulnerability test result
endpoint_details.bleichenbacher|ROBOT/Bleichenbacher oracle test result
endpoint_details.zombiePoodle|Zombie POODLE test result
endpoint_details.goldenDoodle|GOLDENDOODLE test result
endpoint_details.zeroLengthPaddingOracle|0-length padding oracle test result
endpoint_details.sleepingPoodle|Sleeping POODLE test result
endpoint_details.poodle|POODLE SSL vulnerability signal
endpoint_details.poodleTls|POODLE TLS test result
endpoint_details.fallbackScsv|TLS_FALLBACK_SCSV support
endpoint_details.freak|FREAK vulnerability signal
endpoint_details.hasSct|Certificate Transparency SCT availability bits
endpoint_details.drownErrors|DROWN test error signal
endpoint_details.drownVulnerable|DROWN vulnerability signal
endpoint_details.zeroRTTEnabled|TLS 1.3 0-RTT support signal
certificate_chain.issues|Certificate chain issue flags
protocol.q|Insecure protocol quality flag
suite.q|Insecure or weak cipher suite quality flag
simulation.keySize|Simulated client certificate key size
simulation.sigAlg|Simulated client certificate signature algorithm
hsts_policy.status|HSTS policy status
hsts_preload.status|HSTS preload status
hpkp_policy.status|HPKP policy status
cert.sigAlg|Leaf certificate signature algorithm
cert.revocationStatus|Certificate revocation status
cert.crlRevocationStatus|CRL revocation status
cert.ocspRevocationStatus|OCSP revocation status
cert.dnsCaa|CAA policy support
cert.mustStaple|TLS Feature must-staple support
cert.validationType|Certificate validation type
cert.issues|Certificate issue flags
cert.sct|Embedded SCT availability
cert.keySize|Certificate key size
cert.keyStrength|Certificate equivalent key strength
cert.keyKnownDebianInsecure|Debian weak key vulnerability signal
""".strip().splitlines()


SHODAN_INTERNETDB_FIELDS = """
ip|Queried IP address
ports|Observed open TCP ports
cpes|Observed CPE software identifiers
hostnames|Hostnames associated with the IP
tags|Shodan InternetDB classification tags
vulns|CVE identifiers inferred from service metadata
""".strip().splitlines()


URLHAUS_HOST_FIELDS = """
query_status|Host query status
urlhaus_reference|URLhaus host reference URL
host|Queried host
firstseen|First seen timestamp for host
url_count|Number of observed URLs for host
blacklists.spamhaus_dbl|Spamhaus DBL status from URLhaus host result
blacklists.surbl|SURBL status from URLhaus host result
urls.id|URLhaus URL identifier
urls.urlhaus_reference|URLhaus URL reference
urls.url_status|Observed URL status
urls.date_added|URL added timestamp
urls.threat|URLhaus threat category
urls.reporter|Reporter identifier
urls.larted|Provider report status
urls.takedown_time_seconds|Takedown duration
urls.tags|Tags attached to observed URLs
""".strip().splitlines()


SPAMHAUS_DBL_CODES = """
127.0.1.2|spam_domain|Spam domain
127.0.1.4|phish_domain|Phishing domain
127.0.1.5|malware_domain|Malware domain
127.0.1.6|botnet_cc_domain|Botnet command-and-control domain
127.0.1.102|abused_legit_spam|Abused legitimate spam host
127.0.1.103|abused_spammed_redirector|Abused spammed redirector domain
127.0.1.104|abused_legit_phish|Abused legitimate phishing host
127.0.1.105|abused_legit_malware|Abused legitimate malware host
127.0.1.106|abused_legit_botnet_cc|Abused legitimate botnet command-and-control host
127.0.1.255|ip_query_prohibited|IP query prohibited response
127.255.255.252|dnsbl_typo|DNSBL name typing error
127.255.255.254|anonymous_public_resolver|Anonymous query through public resolver
127.255.255.255|excessive_queries|Excessive number of queries
""".strip().splitlines()


SURBL_CODES = """
4|dm|Disposable email domains
8|ph|Phishing sites
16|mw|Malware sites
32|ct|Click tracker domains
64|abuse|Spam and abuse sites
128|cr|Cracked sites
127.0.0.1|blocked|Public resolver access blocked
""".strip().splitlines()


VIRUSTOTAL_DOMAIN_FIELDS = """
id|Domain object identifier
type|VirusTotal object type
links.self|API object self link
attributes.categories|Vendor categorization map
attributes.creation_date|Domain creation timestamp
attributes.expiration_date|Domain expiration timestamp
attributes.last_dns_records|Last observed DNS records
attributes.last_dns_records_date|Last DNS records observation timestamp
attributes.last_https_certificate|Last observed HTTPS certificate
attributes.last_https_certificate_date|HTTPS certificate observation timestamp
attributes.last_analysis_stats.harmless|Harmless engine count
attributes.last_analysis_stats.malicious|Malicious engine count
attributes.last_analysis_stats.suspicious|Suspicious engine count
attributes.last_analysis_stats.timeout|Timeout engine count
attributes.last_analysis_stats.undetected|Undetected engine count
attributes.last_analysis_results|Per-engine analysis results
attributes.reputation|Community reputation score
attributes.total_votes.harmless|Community harmless votes
attributes.total_votes.malicious|Community malicious votes
attributes.popularity_ranks|Popularity ranking evidence
attributes.registrar|Registrar name
attributes.tags|Domain tags
attributes.jarm|JARM TLS fingerprint
attributes.whois|WHOIS text
attributes.whois_date|WHOIS observation timestamp
""".strip().splitlines()


def write_api_field_index(source: str, kind: str, output_name: str, generated_from: str, rows_spec: list[str], notes: list[str]) -> int:
    rows = []
    for line in rows_spec:
        field, title = line.split("|", 1)
        rows.append(
            {
                "atomic_id": f"{source}.{field}",
                "field": field,
                "title": title,
            }
        )
    output = PROJECT_ROOT / f"catalog/generated/{output_name}"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write(f"kind: domain-score.{kind}\n")
        out.write(f"generated_from: {yaml_string(generated_from)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        for note in notes:
            out.write(f"  - {yaml_string(note)}\n")
        out.write("fields:\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    field: {yaml_string(row['field'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
    print(f"wrote {output} ({len(rows)} {source} API fields)")
    return len(rows)


def write_reputation_code_index(source: str, kind: str, output_name: str, generated_from: str, rows_spec: list[str], notes: list[str]) -> int:
    rows = []
    for line in rows_spec:
        code, label, title = line.split("|", 2)
        rows.append(
            {
                "atomic_id": f"{source}.{label}",
                "code": code,
                "label": label,
                "title": title,
            }
        )
    output = PROJECT_ROOT / f"catalog/generated/{output_name}"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write(f"kind: domain-score.{kind}\n")
        out.write(f"generated_from: {yaml_string(generated_from)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        for note in notes:
            out.write(f"  - {yaml_string(note)}\n")
        out.write("codes:\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    code: {yaml_string(row['code'])}\n")
            out.write(f"    label: {yaml_string(row['label'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
    print(f"wrote {output} ({len(rows)} {source} return codes)")
    return len(rows)


def write_public_reputation_indexes() -> tuple[int, int, int, int]:
    shodan_count = write_api_field_index(
        "shodan_internetdb",
        "shodan-internetdb-field-index",
        "shodan-internetdb-field-index.yaml",
        "https://internetdb.shodan.io/",
        SHODAN_INTERNETDB_FIELDS,
        [
            "Source-specific atomic IDs use shodan_internetdb.<field>.",
            "InternetDB is a public no-key Shodan endpoint for non-commercial use; enterprise license is required for commercial use.",
            "The public API returns open ports, CPEs, hostnames, tags and vulnerabilities but not service banners.",
        ],
    )
    urlhaus_count = write_api_field_index(
        "urlhaus_host",
        "urlhaus-host-field-index",
        "urlhaus-host-field-index.yaml",
        "https://urlhaus-api.abuse.ch/",
        URLHAUS_HOST_FIELDS,
        [
            "Source-specific atomic IDs use urlhaus_host.<field>.",
            "Entries reflect URLhaus host query response fields used for malware/reputation evidence.",
            "Some URLhaus API operations require an Auth-Key; Domain Score currently uses the public host query evidence shape.",
        ],
    )
    spamhaus_count = write_reputation_code_index(
        "spamhaus_dbl",
        "spamhaus-dbl-return-code-index",
        "spamhaus-dbl-return-code-index.yaml",
        "https://www.spamhaus.org/blocklists/domain-blocklist/",
        SPAMHAUS_DBL_CODES,
        [
            "Source-specific atomic IDs use spamhaus_dbl.<label>.",
            "Spamhaus DBL domain lookups return 127.0.1.0/24 codes for listed domains and NXDOMAIN when not listed.",
            "Special 127.255.255.* responses are operational/error states and should not be treated as positive listings.",
        ],
    )
    surbl_count = write_reputation_code_index(
        "surbl",
        "surbl-return-code-index",
        "surbl-return-code-index.yaml",
        "https://www.surbl.org/lists",
        SURBL_CODES,
        [
            "Source-specific atomic IDs use surbl.<label>.",
            "SURBL multi.surbl.org uses a bitmasked A-record last octet for list membership.",
            "127.0.0.1 indicates blocked access and should not be treated as a positive reputation listing.",
        ],
    )
    return shodan_count, urlhaus_count, spamhaus_count, surbl_count


def write_virustotal_domain_index() -> int:
    return write_api_field_index(
        "virustotal_domain",
        "virustotal-domain-field-index",
        "virustotal-domain-field-index.yaml",
        "https://docs.virustotal.com/reference/domain-info",
        VIRUSTOTAL_DOMAIN_FIELDS,
        [
            "Source-specific atomic IDs use virustotal_domain.<field>.",
            "VirusTotal domain API requires a user API key; free tier availability and rate limits are account-dependent.",
            "Enterprise-only relationship collections are intentionally excluded from this free/optional-key field catalog.",
        ],
    )


def write_ssl_labs_index() -> int:
    rows = []
    for line in SSL_LABS_FIELDS:
        field, title = line.split("|", 1)
        rows.append(
            {
                "atomic_id": f"ssl_labs.{field}",
                "object": field.split(".", 1)[0],
                "field": field,
                "title": title,
            }
        )
    output = PROJECT_ROOT / "catalog/generated/ssl-labs-api-field-index.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    object_counts = collections.Counter(row["object"] for row in rows)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.ssl-labs-api-field-index\n")
        out.write("generated_from: 'https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md'\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        out.write("  - Source-specific atomic IDs use ssl_labs.<response-object>.<field>.\n")
        out.write("  - SSL Labs API v4 is a free hosted third-party assessment API with registration/rate-limit terms.\n")
        out.write("  - Entries record externally available TLS/certificate evidence fields, not a local open-source scoring engine.\n")
        write_scalar_map(out, "object_counts", object_counts)
        out.write("fields:\n")
        for row in rows:
            out.write(f"  - atomic_id: {yaml_string(row['atomic_id'])}\n")
            out.write(f"    object: {yaml_string(row['object'])}\n")
            out.write(f"    field: {yaml_string(row['field'])}\n")
            out.write(f"    title: {yaml_string(row['title'])}\n")
    print(f"wrote {output} ({len(rows)} SSL Labs API fields)")
    return len(rows)


def write_manifest(
    greenbone_nvt_count: int,
    greenbone_notus_count: int,
    greenbone_cert_count: int,
    greenbone_gvmd_count: int,
    greenbone_scap_count: int,
    subfinder_provider_count: int,
    amass_provider_count: int,
    mozilla_observatory_count: int,
    ssl_labs_count: int,
    shodan_internetdb_count: int,
    urlhaus_host_count: int,
    spamhaus_dbl_count: int,
    surbl_count: int,
    virustotal_domain_count: int,
) -> None:
    entries = [
        ("nuclei", "catalog/generated/nuclei-template-index.yaml", "template_rule_index", 13375, "nuclei.<template-id>"),
        ("testssl", "catalog/generated/testssl-jsonid-index.yaml", "json_id_index", 107, "testssl.<json-id>"),
        ("zap", "catalog/generated/zap-rule-index.yaml", "plugin_rule_index", 104, "zap.<pluginid>"),
        ("internetnl", "catalog/generated/internetnl-subtest-index.yaml", "subtest_index", 76, "internetnl.<category>.<subtest-id>"),
        ("greenbone", "catalog/generated/greenbone-feed-capability-index.yaml", "feed_capability_index", 9, "greenbone.<feed-family>.<id>"),
        ("greenbone", "catalog/generated/greenbone-nvt-index.yaml.gz", "greenbone_nvt_index", greenbone_nvt_count, "greenbone.nvt.<oid>"),
        ("greenbone", "catalog/generated/greenbone-notus-advisory-index.yaml.gz", "greenbone_notus_advisory_index", greenbone_notus_count, "greenbone.notus.<oid>"),
        ("greenbone", "catalog/generated/greenbone-cert-advisory-index.yaml.gz", "greenbone_cert_advisory_index", greenbone_cert_count, "greenbone.cert.<advisory-id>"),
        ("greenbone", "catalog/generated/greenbone-gvmd-data-object-index.yaml", "greenbone_gvmd_data_object_index", greenbone_gvmd_count, "greenbone.<data-object-type>.<uuid>"),
        ("greenbone", "catalog/generated/greenbone-scap-cve-index.yaml.gz", "greenbone_scap_cve_index", greenbone_scap_count, "greenbone.scap.<cve-id>"),
        ("projectdiscovery", "catalog/generated/projectdiscovery-capability-index.yaml", "capability_index", 43, "projectdiscovery.<tool>.<capability>"),
        ("amass", "catalog/generated/amass-capability-index.yaml", "capability_index", 17, "amass.<command>.<capability>"),
        ("subfinder", "catalog/generated/subfinder-provider-index.yaml", "provider_index", subfinder_provider_count, "subfinder.provider.<name>"),
        ("amass", "catalog/generated/amass-provider-index.yaml", "provider_index", amass_provider_count, "amass.provider.<script-category>.<script-name>"),
        ("mozilla_observatory", "catalog/generated/mozilla-observatory-expectation-index.yaml", "expectation_index", mozilla_observatory_count, "mozilla_observatory.<expectation>"),
        ("ssl_labs", "catalog/generated/ssl-labs-api-field-index.yaml", "api_field_index", ssl_labs_count, "ssl_labs.<response-object>.<field>"),
        ("shodan_internetdb", "catalog/generated/shodan-internetdb-field-index.yaml", "api_field_index", shodan_internetdb_count, "shodan_internetdb.<field>"),
        ("urlhaus_host", "catalog/generated/urlhaus-host-field-index.yaml", "api_field_index", urlhaus_host_count, "urlhaus_host.<field>"),
        ("spamhaus_dbl", "catalog/generated/spamhaus-dbl-return-code-index.yaml", "reputation_code_index", spamhaus_dbl_count, "spamhaus_dbl.<label>"),
        ("surbl", "catalog/generated/surbl-return-code-index.yaml", "reputation_code_index", surbl_count, "surbl.<label>"),
        ("virustotal_domain", "catalog/generated/virustotal-domain-field-index.yaml", "api_field_index", virustotal_domain_count, "virustotal_domain.<field>"),
    ]
    output = PROJECT_ROOT / "catalog/generated/source-catalog-manifest.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as out:
        out.write("schema_version: 1\n")
        out.write("kind: domain-score.source-catalog-manifest\n")
        out.write(f"generated_from: {yaml_string(SOURCE_IMAGE)}\n")
        out.write(f'generated_at: "{GENERATED_AT}"\n')
        out.write("notes:\n")
        out.write("  - This manifest lists generated source catalogs used by the product atomic-check catalog.\n")
        out.write("  - Counts reflect the inspected tools image and static capability definitions in the generator.\n")
        out.write("sources:\n")
        for source, path, index_type, count, pattern in entries:
            out.write(f"  - source: {yaml_string(source)}\n")
            out.write(f"    path: {yaml_string(path)}\n")
            out.write(f"    index_type: {yaml_string(index_type)}\n")
            out.write(f"    count: {count}\n")
            out.write(f"    atomic_id_pattern: {yaml_string(pattern)}\n")
    print(f"wrote {output} ({len(entries)} generated source catalogs)")


def main() -> None:
    write_nuclei_index()
    write_testssl_index()
    write_zap_index()
    write_internetnl_index()
    write_greenbone_index()
    greenbone_nvt_count = write_greenbone_nvt_index()
    greenbone_notus_count = write_greenbone_notus_index()
    greenbone_cert_count = write_greenbone_cert_index()
    greenbone_gvmd_count = write_greenbone_gvmd_data_index()
    greenbone_scap_count = write_greenbone_scap_cve_index()
    write_projectdiscovery_index()
    write_amass_index()
    subfinder_provider_count = write_subfinder_provider_index()
    amass_provider_count = write_amass_provider_index()
    mozilla_observatory_count = write_mozilla_observatory_index()
    ssl_labs_count = write_ssl_labs_index()
    (
        shodan_internetdb_count,
        urlhaus_host_count,
        spamhaus_dbl_count,
        surbl_count,
    ) = write_public_reputation_indexes()
    virustotal_domain_count = write_virustotal_domain_index()
    write_manifest(
        greenbone_nvt_count,
        greenbone_notus_count,
        greenbone_cert_count,
        greenbone_gvmd_count,
        greenbone_scap_count,
        subfinder_provider_count,
        amass_provider_count,
        mozilla_observatory_count,
        ssl_labs_count,
        shodan_internetdb_count,
        urlhaus_host_count,
        spamhaus_dbl_count,
        surbl_count,
        virustotal_domain_count,
    )


if __name__ == "__main__":
    main()
