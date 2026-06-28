from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


# Support both:
# - posix-ish: "src/a.c:12: warning: msg"
# - windows absolute: "c:\path\to\a.c:12:34: warning: msg"
# We make file non-greedy to keep the rightmost ":<line>" as the separator.
_RAW_LOC_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?:\s*(?:(?P<sev>\w+)\s*:\s*)?(?P<msg>.*)$"
)


@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str
    raw: str
    tool: str
    rule: str
    file: str | None
    line: int | None
    col: int | None
    severity: str | None
    message: str | None
    metadata: dict[str, Any]

    def dedup_key(self) -> str:
        parts = [
            self.tool or "",
            self.rule or "",
            self.file or "",
            str(self.line or ""),
            str(self.col or ""),
            (self.message or "").strip(),
        ]
        return "\u0001".join(parts)


def _stable_id(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def parse_raw_location(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    m = _RAW_LOC_RE.match(raw)
    if not m:
        return {
            "file": None,
            "line": None,
            "col": None,
            "severity": None,
            "message": raw if raw else None,
        }
    gd = m.groupdict()
    return {
        "file": gd.get("file"),
        "line": int(gd["line"]) if gd.get("line") else None,
        "col": int(gd["col"]) if gd.get("col") else None,
        "severity": (gd.get("sev") or None),
        "message": (gd.get("msg") or "").strip() or None,
    }


def normalize_finding(obj: dict[str, Any]) -> NormalizedFinding:
    raw = str(obj.get("raw", "")).strip()
    tool = str(obj.get("tool", obj.get("source", "generic")) or "generic")
    rule = str(obj.get("rule", obj.get("checker", "")) or "")
    # Prefer structured location when available
    loc_obj = obj.get("location") if isinstance(obj.get("location"), dict) else None
    if loc_obj and (loc_obj.get("file") or loc_obj.get("line") or loc_obj.get("col")):
        loc = {
            "file": loc_obj.get("file"),
            "line": loc_obj.get("line"),
            "col": loc_obj.get("col"),
            "severity": obj.get("severity") or None,
            "message": (obj.get("message") or None),
        }
    else:
        loc = parse_raw_location(raw)
    metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    base_for_id = json.dumps(
        {
            "raw": raw,
            "tool": tool,
            "rule": rule,
            "file": loc["file"],
            "line": loc["line"],
            "col": loc["col"],
            "severity": loc["severity"],
            "message": loc["message"],
            "metadata": metadata,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    finding_id = str(obj.get("finding_id") or obj.get("id") or _stable_id(base_for_id))
    return NormalizedFinding(
        finding_id=finding_id,
        raw=raw,
        tool=tool,
        rule=rule,
        file=loc["file"],
        line=loc["line"],
        col=loc["col"],
        severity=loc["severity"],
        message=loc["message"],
        metadata=metadata,
    )


def categorize(n: NormalizedFinding) -> str:
    """
    Coarse defect category for reporting/LLM conditioning.
    """
    rule = (n.rule or "").lower()
    msg = (n.message or n.raw or "").lower()
    cwe = str((n.metadata or {}).get("cwe") or "").strip()

    if "doublefree" in rule or "double free" in msg:
        return "memory/double_free"
    if any(k in rule for k in ["memleak", "resourceleak"]) or "memory leak" in msg:
        return "resource/leak"
    if "nullpointer" in rule or "null pointer" in msg:
        return "memory/null_pointer"
    if "dealloc" in rule or "use after free" in msg or "deallocated" in msg:
        return "memory/use_after_free"
    if "gets" in msg or "gets" in rule:
        return "api/unsafe_function"
    if "pointeroutofbounds" in rule or "out of bounds" in msg:
        return "memory/out_of_bounds"
    if "uninit" in rule or "uninitialized" in msg:
        return "memory/uninitialized"

    if cwe in {"415"}:
        return "memory/double_free"
    if cwe in {"401", "775"}:
        return "resource/leak"
    if cwe in {"476"}:
        return "memory/null_pointer"
    if cwe in {"672"}:
        return "memory/use_after_free"
    if cwe in {"457"}:
        return "memory/uninitialized"

    return "other"


def _top_counts(items: list[dict[str, Any]], key: str, top_n: int = 8) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for it in items:
        k = str(it.get(key) or "")
        counts[k] = counts.get(k, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    return [{"key": k, "count": v} for k, v in ranked[:top_n]]


def load_findings(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []

    # 1) JSON object with "findings"
    if text.startswith("{"):
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
            return obj["findings"]
        if isinstance(obj, list):
            return obj
        raise ValueError(f"Unsupported JSON object format in {p}")

    # 2) JSONL (one json per line)
    findings: list[dict[str, Any]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            v = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSONL at line {i} in {p}: {e}") from e
        if not isinstance(v, dict):
            raise ValueError(f"JSONL line {i} is not an object in {p}")
        findings.append(v)
    return findings


@dataclass(frozen=True)
class RuleSet:
    """
    A minimal, transparent rule-layer used BEFORE any LLM.

    - deny_raw_regex: matches against full `raw`
    - deny_message_regex: matches against parsed `message`
    - deny_file_regex: matches against parsed `file`
    - allow_*: if provided, only matches passing allow are kept (after deny checks)
    """

    deny_raw_regex: tuple[str, ...] = ()
    deny_message_regex: tuple[str, ...] = ()
    deny_file_regex: tuple[str, ...] = ()
    deny_rule_regex: tuple[str, ...] = ()
    deny_tool_regex: tuple[str, ...] = ()
    deny_severity: tuple[str, ...] = ()
    allow_raw_regex: tuple[str, ...] = ()
    allow_message_regex: tuple[str, ...] = ()
    allow_file_regex: tuple[str, ...] = ()
    allow_rule_regex: tuple[str, ...] = ()
    allow_tool_regex: tuple[str, ...] = ()
    allow_severity: tuple[str, ...] = ()

    @staticmethod
    def from_json(path: str | Path) -> "RuleSet":
        p = Path(path)
        obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(obj, dict):
            raise ValueError(f"Ruleset must be a JSON object: {p}")
        return RuleSet(
            deny_raw_regex=tuple(obj.get("deny_raw_regex", []) or []),
            deny_message_regex=tuple(obj.get("deny_message_regex", []) or []),
            deny_file_regex=tuple(obj.get("deny_file_regex", []) or []),
            deny_rule_regex=tuple(obj.get("deny_rule_regex", []) or []),
            deny_tool_regex=tuple(obj.get("deny_tool_regex", []) or []),
            deny_severity=tuple(obj.get("deny_severity", []) or []),
            allow_raw_regex=tuple(obj.get("allow_raw_regex", []) or []),
            allow_message_regex=tuple(obj.get("allow_message_regex", []) or []),
            allow_file_regex=tuple(obj.get("allow_file_regex", []) or []),
            allow_rule_regex=tuple(obj.get("allow_rule_regex", []) or []),
            allow_tool_regex=tuple(obj.get("allow_tool_regex", []) or []),
            allow_severity=tuple(obj.get("allow_severity", []) or []),
        )


def _any_match(regexes: Iterable[str], text: str) -> bool:
    for r in regexes:
        if re.search(r, text, flags=re.IGNORECASE):
            return True
    return False


def ruleset_decision(n: NormalizedFinding, rules: RuleSet) -> tuple[bool, str]:
    """
    Return (keep, reason). Reason is stable for reporting.
    """
    raw = n.raw or ""
    msg = n.message or ""
    file = n.file or ""
    rule = n.rule or ""
    tool = n.tool or ""
    sev = (n.severity or "").lower()

    # Deny first
    if rules.deny_raw_regex and _any_match(rules.deny_raw_regex, raw):
        return False, "deny_raw_regex"
    if rules.deny_message_regex and _any_match(rules.deny_message_regex, msg):
        return False, "deny_message_regex"
    if rules.deny_file_regex and _any_match(rules.deny_file_regex, file):
        return False, "deny_file_regex"
    if rules.deny_rule_regex and _any_match(rules.deny_rule_regex, rule):
        return False, "deny_rule_regex"
    if rules.deny_tool_regex and _any_match(rules.deny_tool_regex, tool):
        return False, "deny_tool_regex"
    if rules.deny_severity and sev in {s.lower() for s in rules.deny_severity}:
        return False, "deny_severity"

    # Allow filters (opt-in narrowing)
    if rules.allow_raw_regex and not _any_match(rules.allow_raw_regex, raw):
        return False, "allow_raw_regex(no_match)"
    if rules.allow_message_regex and not _any_match(rules.allow_message_regex, msg):
        return False, "allow_message_regex(no_match)"
    if rules.allow_file_regex and not _any_match(rules.allow_file_regex, file):
        return False, "allow_file_regex(no_match)"
    if rules.allow_rule_regex and not _any_match(rules.allow_rule_regex, rule):
        return False, "allow_rule_regex(no_match)"
    if rules.allow_tool_regex and not _any_match(rules.allow_tool_regex, tool):
        return False, "allow_tool_regex(no_match)"
    if rules.allow_severity and sev not in {s.lower() for s in rules.allow_severity}:
        return False, "allow_severity(no_match)"

    return True, "kept"


def heuristic_fp_flag(n: NormalizedFinding) -> tuple[bool, str]:
    """
    A tiny heuristic that only uses static text (no model), for *prioritization*.
    It never marks as "true bug"; it only flags "likely_fp" when evidence is weak.
    """
    msg = (n.message or n.raw or "").lower()
    if any(k in msg for k in ["potential", "may be", "might be", "could be", "possibly"]):
        return True, "weak_modal_language"
    if any(k in msg for k in ["thread safety", "style", "dead code", "redundant"]):
        return True, "non_security_or_style_warning"
    return False, "no_fp_signal"


def triage(
    input_path: str | Path,
    output_path: str | Path,
    ruleset_path: str | Path | None = None,
    sample_per_bucket: int = 3,
) -> dict[str, Any]:
    raw_findings = load_findings(input_path)
    normalized = [normalize_finding(x) for x in raw_findings]

    # Dedup
    seen: set[str] = set()
    deduped: list[NormalizedFinding] = []
    for n in normalized:
        k = n.dedup_key()
        if k in seen:
            continue
        seen.add(k)
        deduped.append(n)

    rules = RuleSet() if ruleset_path is None else RuleSet.from_json(ruleset_path)

    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for n in deduped:
        keep, rule_reason = ruleset_decision(n, rules)
        likely_fp, fp_reason = heuristic_fp_flag(n)
        category = categorize(n)
        out = {
            "finding_id": n.finding_id,
            "raw": n.raw,
            "tool": n.tool,
            "rule": n.rule,
            "file": n.file,
            "line": n.line,
            "col": n.col,
            "severity": n.severity,
            "message": n.message,
            "rule_decision": "keep" if keep else "drop",
            "rule_reason": rule_reason,
            "rule_likely_fp": bool(likely_fp),
            "rule_fp_reason": fp_reason,
            "category": category,
            "metadata": n.metadata or {},
        }
        (kept if keep else dropped).append(out)

    def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for it in items:
            k = str(it.get(key) or "")
            out[k] = out.get(k, 0) + 1
        return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))

    report = {
        "summary": {
            "input_findings": len(raw_findings),
            "normalized": len(normalized),
            "deduped": len(deduped),
            "kept": len(kept),
            "dropped": len(dropped),
            "kept_by_tool": _count_by(kept, "tool"),
            "kept_by_rule": _count_by(kept, "rule"),
            "dropped_by_reason": _count_by(dropped, "rule_reason"),
            "likely_fp_in_kept": sum(1 for x in kept if x.get("rule_likely_fp")),
        },
        "analysis": {},
        "kept": kept,
        "dropped": dropped,
        "samples": {},
    }

    report["analysis"] = {
        "keep_rate": (len(kept) / len(deduped)) if deduped else 0.0,
        "top_kept_rules": _top_counts(kept, "rule"),
        "top_dropped_reasons": _top_counts(dropped, "rule_reason"),
        "top_categories": _top_counts(kept, "category"),
        "likely_fp_examples": [x for x in kept if x.get("rule_likely_fp")][:sample_per_bucket],
    }

    #典型样例：按 rule_reason / fp_reason 分桶
    for bucket_key in ["rule_reason", "rule_fp_reason"]:
        buckets: dict[str, list[dict[str, Any]]] = {}
        for it in kept:
            b = str(it.get(bucket_key) or "")
            buckets.setdefault(b, []).append(it)
        report["samples"][bucket_key] = {
            b: xs[:sample_per_bucket] for b, xs in buckets.items()
        }

    Path(output_path).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report


def _read_text_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _render_context_snippet(
    lines: list[str],
    line_1_based: int,
    before: int,
    after: int,
    path_label: str,
) -> str:
    total = len(lines)
    if total == 0:
        return f"{path_label}\n(empty file)"

    center = max(1, min(line_1_based, total))
    start = max(1, center - before)
    end = min(total, center + after)

    width = len(str(end))
    out: list[str] = [f"{path_label}"]
    for ln in range(start, end + 1):
        prefix = ">>" if ln == center else "  "
        out.append(f"{prefix} {str(ln).rjust(width)} | {lines[ln - 1]}")
    return "\n".join(out)


def enrich_code_context(
    triage_report_path: str | Path,
    code_root: str | Path,
    output_path: str | Path | None = None,
    before: int = 30,
    after: int = 10,
) -> dict[str, Any]:
    """
    Fill `code_context` for each item using (file, line) under `code_root`.

    This is intentionally simple:
    - file path is treated as relative to code_root (after stripping leading './' or '/')
    - if file is missing, code_context is left as null and an error is recorded
    """
    p = Path(triage_report_path)
    report = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    root = Path(code_root)

    missing: list[dict[str, Any]] = []
    updated = 0

    for bucket in ["kept", "dropped"]:
        items = report.get(bucket, []) or []
        for it in items:
            if it.get("code_context"):
                continue

            file_field = (it.get("file") or "").strip()
            line = it.get("line")
            if not file_field or not isinstance(line, int):
                continue

            # Support both relative paths ("src/a.c") and absolute Windows paths ("C:\...\a.c")
            # If absolute and under code_root, we still prefer treating it as relative for stability.
            raw_path = Path(file_field)
            if raw_path.is_absolute():
                try:
                    rel = raw_path.resolve().relative_to(root.resolve())
                    fpath = (root / rel).resolve()
                except Exception:
                    fpath = raw_path.resolve()
            else:
                rel = file_field.lstrip("/").lstrip("\\")
                if rel.startswith("./"):
                    rel = rel[2:]
                fpath = (root / rel).resolve()

            lines = _read_text_lines(fpath)
            if lines is None:
                # Fallback: if path is garbled/absolute, try extracting a relative tail starting at "src/"
                norm = file_field.replace("\\", "/")
                idx = norm.lower().rfind("/src/")
                if idx != -1:
                    rel2 = norm[idx + 1 :]  # drop leading "/"
                    fpath2 = (root / rel2).resolve()
                    lines = _read_text_lines(fpath2)
                    if lines is not None:
                        fpath = fpath2

            if lines is None:
                missing.append(
                    {
                        "finding_id": it.get("finding_id"),
                        "file": it.get("file"),
                        "line": it.get("line"),
                        "resolved_path": str(fpath),
                    }
                )
                continue

            it["code_context"] = _render_context_snippet(
                lines=lines,
                line_1_based=line,
                before=before,
                after=after,
                path_label=f"{it.get('file')}:{line}",
            )
            updated += 1

    report.setdefault("summary", {})
    report["summary"]["code_context_filled"] = updated
    report["summary"]["code_context_missing"] = len(missing)
    report["missing_code_context"] = missing

    out_path = Path(output_path) if output_path else p
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def export_for_llm(
    triage_report_path: str | Path,
    output_jsonl_path: str | Path,
    include_dropped: bool = False,
) -> int:
    """
    Export a stable JSONL contract for teammate-B (LLM judgement).
    """
    p = Path(triage_report_path)
    obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    items: list[dict[str, Any]] = []
    items.extend(obj.get("kept", []) or [])
    if include_dropped:
        items.extend(obj.get("dropped", []) or [])

    out_lines: list[str] = []
    for it in items:
        out_obj = {
            "id": it.get("finding_id"),
            "raw": it.get("raw"),
            "tool": it.get("tool"),
            "rule": it.get("rule"),
            "location": {
                "file": it.get("file"),
                "line": it.get("line"),
                "col": it.get("col"),
            },
            "message": it.get("message"),
            "severity": it.get("severity"),
            # optional: rule layer hints (B can ignore)
            "rule_layer": {
                "decision": it.get("rule_decision"),
                "reason": it.get("rule_reason"),
                "likely_fp": it.get("rule_likely_fp"),
                "fp_reason": it.get("rule_fp_reason"),
            },
            # reserved for later enrichment
            "code_context": it.get("code_context") or None,
            "metadata": {
                **(it.get("metadata") or {}),
                # keep additions non-breaking by living in metadata
                "category": it.get("category") or None,
            },
        }
        out_lines.append(json.dumps(out_obj, ensure_ascii=False))

    Path(output_jsonl_path).write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return len(out_lines)

