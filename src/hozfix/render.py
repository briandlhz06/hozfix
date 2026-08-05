from __future__ import annotations

from hozfix.model import Fix


def render_markdown(fixes: list[Fix], *, hostname: str = "") -> str:
    lines: list[str] = ["# Hozfix", ""]
    if hostname:
        lines.append(f"Host: `{hostname}`")
        lines.append("")
    if not fixes:
        lines.append("Nada para arreglar con receta. O el reporte solo tenía info/skip.")
        lines.append("")
        return "\n".join(lines)

    n = len(fixes)
    lines.append(
        f"{n} fixes. Orden: acceso SSH -> datos/servicios -> perímetro (UFW/fail2ban) -> updates/reboot."
    )
    lines.append("")
    lines.append("## Resumen")
    lines.append("")
    for i, fix in enumerate(fixes, 1):
        lines.append(f"{i}. [{fix.severity.upper()}] {fix.label} - {fix.title}")
    lines.append("")

    for i, fix in enumerate(fixes, 1):
        sev = fix.severity.upper()
        if fix.id == "HOZ-SSH-BUNDLE" and fix.source_ids:
            id_label = f"{fix.id} ({'+'.join(fix.source_ids)})"
        else:
            id_label = fix.label
        lines.append(f"## {i}. [{sev}] {id_label} - {fix.title}")
        lines.append("")
        if fix.hallazgo:
            lines.append(fix.hallazgo)
            lines.append("")
        if fix.evidencia:
            lines.append("```text")
            lines.append(fix.evidencia.rstrip())
            lines.append("```")
            lines.append("")
        if fix.prerequisites:
            lines.append("Antes:")
            for p in fix.prerequisites:
                lines.append(f"- {p}")
            lines.append("")
        if fix.warnings:
            for w in fix.warnings:
                lines.append(f"**{w}**")
            lines.append("")
        if fix.commands:
            lines.append("```bash")
            for cmd in fix.commands:
                lines.append(cmd)
            lines.append("```")
            lines.append("")
        if fix.verify:
            lines.append("Verificar:")
            lines.append("")
            lines.append("```bash")
            for v in fix.verify:
                lines.append(v)
            lines.append("```")
            lines.append("")
        if fix.note:
            lines.append(fix.note)
            lines.append("")
    return "\n".join(lines)


def _shell_quote_for_c(cmd: str) -> str:
    """Single-quote a command string for bash -c '...'."""
    return "'" + cmd.replace("'", "'\\''") + "'"


def render_shell(fixes: list[Fix], *, hostname: str = "") -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# Hozfix: plan sugerido. Revisá antes de pegar en prod.",
        "# Uso: sudo bash fix.sh   |   bash fix.sh --dry-run",
        "# run_sh usa bash -c (sin eval). apply_block usa bash -s sobre el heredoc.",
        "set -euo pipefail",
        "",
        "DRY=0",
        '[[ "${1:-}" == "--dry-run" ]] && DRY=1',
        "",
        "run_sh() {",
        '  if [[ "$DRY" == "1" ]]; then',
        '    printf "+ %s\\n" "$1"',
        "    return 0",
        "  fi",
        '  bash -c "$1"',
        "}",
        "",
        "apply_block() {",
        '  if [[ "$DRY" == "1" ]]; then',
        '    printf "+ (bloque)\\n"',
        "    cat",
        "    return 0",
        "  fi",
        "  bash -s",
        "}",
        "",
    ]
    if hostname:
        lines.append(f"# host: {hostname}")
        lines.append("")
    if not fixes:
        lines.append("echo 'Nada accionable.'")
        lines.append("")
        return "\n".join(lines)

    for i, fix in enumerate(fixes, 1):
        lines.append(f"# {i}. [{fix.severity.upper()}] {fix.id} - {fix.title}")
        if fix.warnings:
            for w in fix.warnings:
                lines.append(f"# WARN: {w}")
        if fix.prerequisites:
            for p in fix.prerequisites:
                lines.append(f"# antes: {p}")
        if fix.note:
            for note_line in fix.note.splitlines():
                lines.append(f"# {note_line}")

        has_heredoc = any("<<" in c for c in fix.commands)
        if has_heredoc:
            lines.append("apply_block <<'HOZ_BLOCK'")
            for cmd in fix.commands:
                lines.append(cmd)
            lines.append("HOZ_BLOCK")
        else:
            for cmd in fix.commands:
                if cmd.startswith("#"):
                    lines.append(cmd)
                else:
                    lines.append(f"run_sh {_shell_quote_for_c(cmd)}")
        if fix.verify:
            lines.append("# verificar:")
            for v in fix.verify:
                if v.startswith("#"):
                    lines.append(v)
                else:
                    lines.append(f"run_sh {_shell_quote_for_c(v)}")
        lines.append("")
    return "\n".join(lines)
