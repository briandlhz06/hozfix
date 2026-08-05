from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hozfix import __version__
from hozfix.render import render_markdown, render_shell
from hozfix.util import build_fixes, findings_from_ids, load_findings, missing_recipes, parse_ids


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="hozfix",
        description="Hozfix - día 2: qué tocás ahora (post Hoztage).",
    )
    p.add_argument("--from-json", type=Path, default=None, help="Reporte JSON de Hoztage")
    p.add_argument("--ids", default="", help="IDs HOZ-... separados por coma")
    p.add_argument("--md", type=Path, default=None, help="Guardar Markdown")
    p.add_argument("--sh", type=Path, default=None, help="Guardar script shell")
    p.add_argument(
        "--all",
        action="store_true",
        help="Incluir info/skip si hay receta (por defecto solo critical/high/medium)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Imprimí el plan y no escribas --md/--sh (revisá antes)",
    )
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--stdout-md", action="store_true")
    p.add_argument("--version", action="version", version=f"hozfix {__version__}")
    args = p.parse_args(argv)

    if not args.from_json and not args.ids:
        p.error("Pedí --from-json y/o --ids")

    findings = []
    hostname = ""
    only_actionable = not args.all

    try:
        if args.from_json:
            if not args.from_json.is_file():
                print(f"No está el JSON: {args.from_json}", file=sys.stderr)
                return 1
            findings.extend(load_findings(args.from_json))
            try:
                raw = json.loads(args.from_json.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    hostname = str(raw.get("hostname") or "")
            except json.JSONDecodeError:
                pass
        if args.ids:
            id_findings = findings_from_ids(parse_ids(args.ids))
            if args.from_json:
                by_id = {f.id: f for f in findings}
                merged = []
                for f in id_findings:
                    merged.append(by_id.get(f.id, f))
                findings = merged
                only_actionable = False
            else:
                findings = id_findings
                only_actionable = False
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"No pude leer el input: {e}", file=sys.stderr)
        return 1

    fixes = build_fixes(findings, only_actionable=only_actionable, hostname=hostname)
    missed = missing_recipes(findings, only_actionable=only_actionable, hostname=hostname)

    if not args.quiet:
        print(f"{len(fixes)} fixes.", flush=True)
        if missed:
            print(f"Sin receta: {', '.join(missed)}", flush=True)
        if args.dry_run:
            print("dry-run: no escribo archivos.", flush=True)

    md = render_markdown(fixes, hostname=hostname)
    sh = render_shell(fixes, hostname=hostname)

    if not args.dry_run:
        if args.md:
            args.md.parent.mkdir(parents=True, exist_ok=True)
            args.md.write_text(md, encoding="utf-8")
            if not args.quiet:
                print(f"md: {args.md}")
        if args.sh:
            args.sh.parent.mkdir(parents=True, exist_ok=True)
            args.sh.write_text(sh, encoding="utf-8")
            if not args.quiet:
                print(f"sh: {args.sh}")

    if args.dry_run or args.stdout_md or (not args.md and not args.sh):
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
