from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure `src/` import works when running from scripts/
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from a_rule_triage import export_for_llm, triage  # noqa: E402
from a_rule_triage import enrich_code_context  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="Rule-layer triage utilities (teammate A)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_triage = sub.add_parser("triage", help="Dedup + regex rule filtering + summary.")
    p_triage.add_argument("--input_path", required=True)
    p_triage.add_argument("--output_path", required=True)
    p_triage.add_argument("--ruleset_path", default=None)
    p_triage.add_argument("--sample_per_bucket", type=int, default=3)

    p_export = sub.add_parser(
        "export_for_llm", help="Export JSONL contract for LLM judgement."
    )
    p_export.add_argument("--triage_report_path", required=True)
    p_export.add_argument("--output_jsonl_path", required=True)
    p_export.add_argument("--include_dropped", action="store_true", default=False)

    p_ctx = sub.add_parser(
        "enrich_code_context",
        help="Fill code_context from a code root using (file,line).",
    )
    p_ctx.add_argument("--triage_report_path", required=True)
    p_ctx.add_argument("--code_root", required=True)
    p_ctx.add_argument("--output_path", default=None)
    p_ctx.add_argument("--before", type=int, default=30)
    p_ctx.add_argument("--after", type=int, default=10)

    args = parser.parse_args()

    if args.cmd == "triage":
        triage(
            input_path=args.input_path,
            output_path=args.output_path,
            ruleset_path=args.ruleset_path,
            sample_per_bucket=args.sample_per_bucket,
        )
        return

    if args.cmd == "export_for_llm":
        export_for_llm(
            triage_report_path=args.triage_report_path,
            output_jsonl_path=args.output_jsonl_path,
            include_dropped=args.include_dropped,
        )
        return

    if args.cmd == "enrich_code_context":
        enrich_code_context(
            triage_report_path=args.triage_report_path,
            code_root=args.code_root,
            output_path=args.output_path,
            before=args.before,
            after=args.after,
        )
        return

    raise SystemExit(f"Unknown command: {args.cmd}")


if __name__ == "__main__":
    main()

