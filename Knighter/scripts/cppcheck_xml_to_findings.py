from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any, Iterable


def _stable_id(parts: dict[str, Any]) -> str:
    s = json.dumps(parts, ensure_ascii=False, sort_keys=True)
    return hashlib.md5(s.encode("utf-8", errors="replace")).hexdigest()


_ERROR_OPEN_RE = re.compile(r"<error\s+([^>]+)>")
_LOCATION_RE = re.compile(r"<location\s+([^/>]+)/?>")
_ATTR_RE = re.compile(r"(\w+)=\"([^\"]*)\"")


def _parse_attrs(attr_text: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for k, v in _ATTR_RE.findall(attr_text):
        # cppcheck uses XML entities like &apos;
        attrs[k] = html.unescape(v)
    return attrs


def _iter_error_blocks(lines: Iterable[str]) -> Iterable[list[str]]:
    cur: list[str] = []
    in_err = False
    for line in lines:
        if "<error " in line:
            in_err = True
            cur = [line]
            continue
        if in_err:
            cur.append(line)
            if "</error>" in line:
                yield cur
                in_err = False
                cur = []


def parse_cppcheck_xml(xml_path: str | Path) -> list[dict[str, Any]]:
    p = Path(xml_path)
    # NOTE: Some Windows cppcheck builds may emit non-UTF8 bytes while declaring UTF-8,
    # which breaks strict XML parsers. We do a tolerant line-based parse instead.
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    findings: list[dict[str, Any]] = []
    for block in _iter_error_blocks(lines):
        open_line = block[0]
        m = _ERROR_OPEN_RE.search(open_line)
        if not m:
            continue
        err_attrs = _parse_attrs(m.group(1))

        rule = err_attrs.get("id", "")
        severity = err_attrs.get("severity")
        msg = err_attrs.get("msg") or err_attrs.get("verbose") or ""
        cwe = err_attrs.get("cwe") or None
        file0 = err_attrs.get("file0") or None

        # first location in block
        file_path = None
        line_no: int | None = None
        col_no: int | None = None
        for bl in block[1:]:
            lm = _LOCATION_RE.search(bl)
            if not lm:
                continue
            loc_attrs = _parse_attrs(lm.group(1))
            file_path = loc_attrs.get("file") or file0
            ln = loc_attrs.get("line")
            cn = loc_attrs.get("column")
            line_no = int(ln) if ln and ln.isdigit() else None
            col_no = int(cn) if cn and cn.isdigit() else None
            break

        # Some Windows builds emit non-UTF8 bytes for <location file="...">,
        # resulting in mojibake after replacement. Prefer file0 when it looks cleaner.
        if file0 and file_path:
            if "\ufffd" in file_path or "����" in file_path:
                file_path = file0
        file_path = file_path or file0

        # Normalize to a stable relative-ish shape when possible
        raw_parts = []
        if file_path:
            raw_parts.append(str(file_path))
        if line_no is not None:
            raw_parts.append(str(line_no))
        if col_no is not None:
            raw_parts.append(str(col_no))
        raw_prefix = ":".join(raw_parts) if raw_parts else ""
        raw = f"{raw_prefix}: {severity}: {msg}".strip()

        finding_id = _stable_id(
            {
                "tool": "cppcheck",
                "rule": rule,
                "file": file_path,
                "line": line_no,
                "col": col_no,
                "severity": severity,
                "msg": msg,
                "cwe": cwe,
            }
        )
        findings.append(
            {
                "finding_id": finding_id,
                "raw": raw,
                "tool": "cppcheck",
                "rule": rule,
                "severity": severity,
                "message": msg,
                "location": {"file": file_path, "line": line_no, "col": col_no},
                "metadata": {"cwe": cwe} if cwe else {},
            }
        )
    return findings


def main():
    ap = argparse.ArgumentParser(description="Convert cppcheck XML to findings JSON.")
    ap.add_argument("--xml_path", required=True)
    ap.add_argument("--output_path", required=True)
    args = ap.parse_args()

    findings = parse_cppcheck_xml(args.xml_path)
    out = {"summary": {"total": len(findings), "by_tool": {"cppcheck": len(findings)}}, "findings": findings}
    Path(args.output_path).write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()

