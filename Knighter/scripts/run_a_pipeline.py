from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="One-shot pipeline for teammate A (cppcheck -> findings -> triage -> context -> jsonl)."
    )
    ap.add_argument(
        "--workspace_root",
        required=True,
        help="Root folder, e.g. C:\\Users\\11452\\Desktop\\software quality assurance",
    )
    ap.add_argument(
        "--cppcheck_exe",
        required=True,
        help="Path to cppcheck.exe, e.g. E:\\cppcheck.exe",
    )
    ap.add_argument(
        "--code_root",
        default=None,
        help="Target code root. Default: <workspace_root>\\code\\sample_target",
    )
    ap.add_argument(
        "--ruleset_path",
        default=None,
        help="Ruleset JSON. Default: a_ruleset.cppcheck_focus.json if present, else a_ruleset.example.json",
    )
    ap.add_argument(
        "--platform",
        default="win64",
        help="cppcheck --platform value (default: win64).",
    )
    ap.add_argument(
        "--keep_intermediate",
        action="store_true",
        default=False,
        help="Keep intermediate triage_cppcheck.json (default: false).",
    )
    args = ap.parse_args()

    ws = Path(args.workspace_root)
    if not ws.exists():
        raise SystemExit(f"workspace_root not found: {ws}")

    scripts_dir = ws / "Knighter" / "scripts"
    if not scripts_dir.exists():
        raise SystemExit(f"Knighter scripts dir not found: {scripts_dir}")

    cppcheck_exe = Path(args.cppcheck_exe)
    if not cppcheck_exe.exists():
        raise SystemExit(f"cppcheck.exe not found: {cppcheck_exe}")

    code_root = Path(args.code_root) if args.code_root else (ws / "code" / "sample_target")
    if not code_root.exists():
        raise SystemExit(f"code_root not found: {code_root}")

    if args.ruleset_path:
        ruleset_path = Path(args.ruleset_path)
    else:
        focus = scripts_dir / "a_ruleset.cppcheck_focus.json"
        ruleset_path = focus if focus.exists() else (scripts_dir / "a_ruleset.example.json")
    if not ruleset_path.exists():
        raise SystemExit(f"ruleset_path not found: {ruleset_path}")

    xml_path = ws / "cppcheck.xml"
    findings_path = ws / "cppcheck_findings.json"
    triage_path = ws / "triage_cppcheck.json"
    triage_with_ctx_path = ws / "triage_cppcheck.with_ctx.json"
    out_jsonl_path = ws / "for_llm.cppcheck.with_ctx.jsonl"

    # 1) cppcheck -> XML (stderr)
    # NOTE: cppcheck writes XML to stderr.
    cmd = [
        str(cppcheck_exe),
        f"--platform={args.platform}",
        "--enable=all",
        "--inconclusive",
        "--xml",
        "--xml-version=2",
        "--force",
        "--inline-suppr",
        "--language=c",
        "--std=c11",
        str(code_root),
    ]
    with xml_path.open("w", encoding="utf-8", errors="replace") as f:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=f, cwd=str(ws))
        if proc.returncode != 0:
            raise SystemExit(proc.returncode)

    # 2) XML -> findings JSON
    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "cppcheck_xml_to_findings.py"),
            "--xml_path",
            str(xml_path),
            "--output_path",
            str(findings_path),
        ],
        cwd=ws,
    )

    # 3) triage
    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "a_rule_triage.py"),
            "triage",
            "--input_path",
            str(findings_path),
            "--output_path",
            str(triage_path),
            "--ruleset_path",
            str(ruleset_path),
        ],
        cwd=scripts_dir,
    )

    # 4) enrich code_context
    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "a_rule_triage.py"),
            "enrich_code_context",
            "--triage_report_path",
            str(triage_path),
            "--code_root",
            str(code_root),
            "--output_path",
            str(triage_with_ctx_path),
        ],
        cwd=scripts_dir,
    )

    # 5) export JSONL for LLM
    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "a_rule_triage.py"),
            "export_for_llm",
            "--triage_report_path",
            str(triage_with_ctx_path),
            "--output_jsonl_path",
            str(out_jsonl_path),
        ],
        cwd=scripts_dir,
    )

    if not args.keep_intermediate:
        try:
            triage_path.unlink(missing_ok=True)  # py3.8+ on windows store app should support
        except TypeError:
            if triage_path.exists():
                triage_path.unlink()

    print("OK")
    print(f"- cppcheck xml: {xml_path}")
    print(f"- findings json: {findings_path}")
    print(f"- triage with ctx: {triage_with_ctx_path}")
    print(f"- llm jsonl: {out_jsonl_path}")


if __name__ == "__main__":
    main()

