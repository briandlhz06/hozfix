from __future__ import annotations

import json
from pathlib import Path

from hozfix.ctx import Ctx
from hozfix.model import ACTIONABLE, FindingRef, Fix
from hozfix.recipes import coalesce_ssh, dedupe_fixes, order_fixes, recipe_for


def parse_ids(raw: str) -> list[str]:
    parts = []
    for chunk in raw.replace("\n", ",").split(","):
        item = chunk.strip().upper()
        if item:
            parts.append(item)
    seen: set[str] = set()
    out: list[str] = []
    for i in parts:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def load_findings(path: Path) -> list[FindingRef]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("findings") or []
    else:
        raise ValueError("JSON inválido: esperaba objeto con findings o lista.")

    out: list[FindingRef] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        fid = str(row.get("id") or "").strip()
        if not fid:
            continue
        sev = str(row.get("severity") or "medium").strip().lower()
        out.append(
            FindingRef(
                id=fid.upper() if fid.upper().startswith("HOZ-") else fid,
                title=str(row.get("title") or ""),
                severity=sev,
                hallazgo=str(row.get("hallazgo") or ""),
                evidencia=str(row.get("evidencia") or ""),
                consejo=str(row.get("consejo") or ""),
                area=str(row.get("area") or ""),
            )
        )
    return out


def findings_from_ids(ids: list[str]) -> list[FindingRef]:
    return [FindingRef(id=i, severity="medium") for i in ids]


def build_fixes(
    findings: list[FindingRef],
    *,
    only_actionable: bool = True,
    hostname: str = "",
) -> list[Fix]:
    ctx = Ctx(findings=list(findings), hostname=hostname)
    fixes: list[Fix] = []
    seen: set[str] = set()
    for f in findings:
        if only_actionable and f.severity not in ACTIONABLE:
            continue
        if f.id in seen:
            continue
        fix = recipe_for(f, ctx)
        if fix is None:
            continue
        seen.add(f.id)
        fixes.append(fix)
    fixes = coalesce_ssh(fixes, ctx)
    fixes = dedupe_fixes(fixes)
    return order_fixes(fixes)


def missing_recipes(
    findings: list[FindingRef],
    *,
    only_actionable: bool = True,
    hostname: str = "",
) -> list[str]:
    missing: list[str] = []
    ctx = Ctx(findings=list(findings), hostname=hostname)
    for f in findings:
        if only_actionable and f.severity not in ACTIONABLE:
            continue
        if recipe_for(f, ctx) is None:
            missing.append(f.id)
    return missing
