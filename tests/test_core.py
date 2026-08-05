from __future__ import annotations

import json
from pathlib import Path

from hozfix.cli import main
from hozfix.model import FindingRef, PHASE
from hozfix.recipes import lookup, recipe_for
from hozfix.render import render_markdown, render_shell
from hozfix.util import build_fixes, load_findings, parse_ids

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample-input.json"
FIXTURE = Path(__file__).parent / "fixtures" / "sample-report.json"


def test_parse_ids():
    assert parse_ids("hoz-ssh-001, HOZ-NET-004") == ["HOZ-SSH-001", "HOZ-NET-004"]
    assert parse_ids("HOZ-SSH-001,HOZ-SSH-001") == ["HOZ-SSH-001"]


def test_lookup_core_ids():
    assert lookup("HOZ-SSH-001")
    assert lookup("HOZ-NET-006")
    assert lookup("HOZ-FW-003")
    assert not lookup("HOZ-HOST-001")


def test_ssh_uses_dropin():
    fix = recipe_for(FindingRef(id="HOZ-SSH-001", severity="critical", hallazgo="PermitRootLogin yes."))
    assert fix is not None
    blob = "\n".join(fix.commands)
    assert "sshd_config.d/99-hozfix.conf" in blob
    assert "PermitRootLogin no" in blob
    assert "sed -i" not in blob
    assert any("LOCKOUT" in w for w in fix.warnings)
    assert fix.verify
    assert fix.prerequisites


def test_ssh_bundle_when_multiple():
    findings = [
        FindingRef(id="HOZ-SSH-001", severity="critical", hallazgo="PermitRootLogin yes."),
        FindingRef(id="HOZ-SSH-002", severity="high", hallazgo="PasswordAuthentication yes."),
        FindingRef(id="HOZ-SSH-005", severity="info", hallazgo="Port 2222."),
    ]
    fixes = build_fixes(findings, only_actionable=True)
    ids = [f.id for f in fixes]
    assert "HOZ-SSH-BUNDLE" in ids
    assert "HOZ-SSH-001" not in ids
    assert "HOZ-SSH-002" not in ids
    bundle = next(f for f in fixes if f.id == "HOZ-SSH-BUNDLE")
    text = "\n".join(bundle.commands)
    assert "PermitRootLogin no" in text
    assert "PasswordAuthentication no" in text
    assert "sshd_config.d" in text


def test_ufw_uses_ssh_port_from_report():
    findings = [
        FindingRef(id="HOZ-FW-001", severity="high", hallazgo="UFW inactive"),
        FindingRef(id="HOZ-SSH-005", severity="info", hallazgo="Port 2222."),
    ]
    fixes = build_fixes(findings, only_actionable=True)
    fw = next(f for f in fixes if f.id == "HOZ-FW-001")
    assert any("2222/tcp" in c for c in fw.commands)
    assert any("LOCKOUT" in w for w in fw.warnings)


def test_web_patterns_and_path():
    env = recipe_for(
        FindingRef(
            id="HOZ-WEB-001",
            title=".env legible",
            severity="critical",
            evidencia="/var/www/html/.env 0o644",
        )
    )
    assert env is not None
    assert any("/var/www/html/.env" in c for c in env.commands)
    assert "chmod 600" in env.commands[0]
    assert "Reemplazá PATH" not in (env.note or "")


def test_web_missing_path_discovery():
    env = recipe_for(
        FindingRef(id="HOZ-WEB-001", severity="critical", hallazgo=".env legible", evidencia="")
    )
    assert env is not None
    blob = "\n".join(env.commands)
    assert "find" in blob
    assert "Reemplazá PATH" not in blob


def test_mysql_uses_conf_from_evidence():
    fix = recipe_for(
        FindingRef(
            id="HOZ-DB-002",
            severity="high",
            hallazgo="bind-address = 0.0.0.0",
            evidencia="/etc/mysql/mysql.conf.d/mysqld.cnf",
        )
    )
    assert fix is not None
    assert any("/etc/mysql/mysql.conf.d/mysqld.cnf" in c for c in fix.commands)
    assert any("ss -lntp" in c for c in fix.verify)


def test_mysql_missing_path_discovery():
    fix = recipe_for(
        FindingRef(id="HOZ-DB-002", severity="high", hallazgo="bind-address = 0.0.0.0", evidencia="")
    )
    assert fix is not None
    blob = "\n".join(fix.commands)
    assert "grep -Rns" in blob
    assert "/etc/mysql/" in blob


def test_empty_password_users_from_finding():
    fix = recipe_for(
        FindingRef(
            id="HOZ-USR-003",
            severity="critical",
            hallazgo="alice, bob",
            evidencia="alice\nbob",
        )
    )
    assert fix is not None
    assert any("passwd -l alice" in c for c in fix.commands)
    assert any("passwd -l bob" in c for c in fix.commands)


def test_docker_names_from_evidence():
    fix = recipe_for(
        FindingRef(
            id="HOZ-DOCK-010",
            severity="medium",
            evidencia="mailcowdockerized-nginx-mailcow-1\tmailcow/nginx:1.0\t0.0.0.0:8081->80/tcp",
        )
    )
    assert fix is not None
    blob = "\n".join(fix.commands)
    assert "mailcowdockerized-nginx-mailcow-1" in blob
    assert "docker inspect" in blob
    assert "{{.Names}}" in blob


def test_dock_port_ids():
    assert lookup("HOZ-DOCK-6379")
    assert lookup("HOZ-DOCK-3306")


def test_sys_unit_recipe():
    fix = recipe_for(FindingRef(id="HOZ-SYS-nginx", severity="medium", title="Servicio nginx"))
    assert fix is not None
    assert "systemctl status nginx" in fix.commands[0]


def test_dedupe_net004_db002():
    findings = [
        FindingRef(
            id="HOZ-NET-004",
            severity="high",
            hallazgo="MariaDB escucha en 0.0.0.0:3306",
            evidencia="0.0.0.0:3306 LISTEN mysqld",
        ),
        FindingRef(
            id="HOZ-DB-002",
            severity="high",
            hallazgo="bind-address = 0.0.0.0",
            evidencia="/etc/mysql/mysql.conf.d/mysqld.cnf",
        ),
    ]
    fixes = build_fixes(findings)
    ids = [f.id for f in fixes]
    assert "HOZ-NET-004" in ids
    assert "HOZ-DB-002" not in ids
    net = next(f for f in fixes if f.id == "HOZ-NET-004")
    assert "HOZ-DB-002" in net.source_ids
    blob = "\n".join(net.commands)
    assert "ufw deny 3306" in blob
    assert "/etc/mysql/mysql.conf.d/mysqld.cnf" in blob


def test_dedupe_fw003_auth001():
    findings = [
        FindingRef(id="HOZ-FW-003", severity="medium", hallazgo="No encontré fail2ban."),
        FindingRef(id="HOZ-AUTH-001", severity="medium", hallazgo="80 fallos SSH"),
        FindingRef(id="HOZ-SSH-005", severity="info", hallazgo="Port 2222."),
    ]
    fixes = build_fixes(findings)
    ids = [f.id for f in fixes]
    assert "HOZ-FW-003" in ids
    assert "HOZ-AUTH-001" not in ids
    fw = next(f for f in fixes if f.id == "HOZ-FW-003")
    assert "HOZ-AUTH-001" in fw.source_ids
    assert any("2222" in c for c in fw.commands)


def test_dependency_order():
    # Día 2: SSH (acceso) -> .env/datos -> UFW -> reboot
    findings = [
        FindingRef(id="HOZ-UPD-002", severity="medium", hallazgo="reboot"),
        FindingRef(id="HOZ-FW-001", severity="high", hallazgo="UFW inactive"),
        FindingRef(id="HOZ-SSH-001", severity="critical", hallazgo="PermitRootLogin yes."),
        FindingRef(id="HOZ-WEB-001", severity="critical", evidencia="/var/www/html/.env"),
        FindingRef(id="HOZ-NET-004", severity="high", hallazgo="0.0.0.0:3306"),
        FindingRef(id="HOZ-SSH-005", severity="info", hallazgo="Port 22."),
        FindingRef(id="HOZ-HOST-001", severity="info", hallazgo="cliente-wp-07, kernel x"),
    ]
    fixes = build_fixes(findings, hostname="cliente-wp-07")
    phases = [f.phase for f in fixes]
    assert phases == sorted(phases)
    by_id = {f.id: f for f in fixes}
    assert by_id["HOZ-SSH-001"].phase == PHASE["ssh"]
    assert by_id["HOZ-WEB-001"].phase == PHASE["perm"]
    assert by_id["HOZ-NET-004"].phase == PHASE["db"]
    assert by_id["HOZ-FW-001"].phase == PHASE["ufw"]
    assert by_id["HOZ-UPD-002"].phase == PHASE["reboot"]
    assert by_id["HOZ-SSH-001"].phase < by_id["HOZ-WEB-001"].phase
    assert by_id["HOZ-WEB-001"].phase < by_id["HOZ-FW-001"].phase
    assert by_id["HOZ-FW-001"].phase < by_id["HOZ-UPD-002"].phase
    # SSH critical antes que .env critical en el plan
    ids = [f.id for f in fixes]
    assert ids.index("HOZ-SSH-001") < ids.index("HOZ-WEB-001")


def test_ssh_prereqs_use_hostname():
    findings = [
        FindingRef(id="HOZ-SSH-001", severity="critical", hallazgo="PermitRootLogin yes."),
        FindingRef(id="HOZ-SSH-002", severity="high", hallazgo="PasswordAuthentication yes."),
    ]
    fixes = build_fixes(findings, hostname="cliente-wp-07")
    bundle = next(f for f in fixes if f.id == "HOZ-SSH-BUNDLE")
    blob = "\n".join(bundle.prerequisites)
    assert "cliente-wp-07" in blob
    assert "USUARIO@cliente-wp-07" in blob
    assert "whoami" in blob
    assert "OTRA sesión" in blob


def test_ssh_prereqs_discovery_without_host():
    fix = recipe_for(FindingRef(id="HOZ-SSH-001", severity="critical", hallazgo="PermitRootLogin yes."))
    assert fix is not None
    blob = "\n".join(fix.prerequisites)
    assert "hostname -I" in blob
    assert "whoami" in blob
    assert "USUARIO@HOST" not in blob


def test_build_fixes_skips_info():
    findings = load_findings(SAMPLE)
    fixes = build_fixes(findings, only_actionable=True, hostname="cliente-wp-07")
    ids = [f.id for f in fixes]
    assert "HOZ-NET-004" in ids
    assert "HOZ-WEB-001" in ids
    assert "HOZ-SSH-005" not in ids
    assert "HOZ-HOST-001" not in ids
    assert "HOZ-SSH-BUNDLE" in ids
    assert "HOZ-DB-002" not in ids  # dedupe con NET-004
    assert fixes[0].phase <= fixes[-1].phase
    assert ids.index("HOZ-SSH-BUNDLE") < ids.index("HOZ-WEB-001")


def test_ids_force_recipe():
    findings = [FindingRef(id="HOZ-SSH-001", severity="info")]
    assert build_fixes(findings, only_actionable=True) == []
    assert len(build_fixes(findings, only_actionable=False)) == 1


def test_markdown_shape():
    findings = load_findings(SAMPLE)
    fixes = build_fixes(findings, hostname="cliente-wp-07")
    md = render_markdown(fixes, hostname="cliente-wp-07")
    assert "# Hozfix" in md
    assert "## Resumen" in md
    assert "1. [" in md
    assert md.index("HOZ-SSH-BUNDLE") < md.index("HOZ-WEB-001")
    assert "sshd_config.d/99-hozfix.conf" in md
    assert "```bash" in md
    assert "Verificar:" in md
    assert "Antes:" in md
    assert "cliente-wp-07" in md
    assert "Qué hacer:" not in md
    assert "Qué encontré" not in md
    assert "Accion:" not in md
    assert "—" not in md
    assert "/var/www/html/.env" in md
    assert f"{len(fixes)} fixes" in md


def test_shell_shape():
    fixes = build_fixes(load_findings(SAMPLE), hostname="cliente-wp-07")
    sh = render_shell(fixes, hostname="cliente-wp-07")
    assert sh.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in sh
    assert "--dry-run" in sh
    assert "run_sh" in sh
    assert "apply_block" in sh
    assert "bash -c" in sh
    assert "bash -s" in sh
    assert "eval " not in sh
    assert "—" not in sh
    assert "Qué hacer" not in sh


def test_cli_from_json(tmp_path: Path):
    md = tmp_path / "fixes.md"
    sh = tmp_path / "fix.sh"
    code = main(["--from-json", str(SAMPLE), "--md", str(md), "--sh", str(sh), "-q"])
    assert code == 0
    text = md.read_text(encoding="utf-8")
    assert "HOZ-NET-004" in text
    assert "ufw deny 3306" in text
    assert "## Resumen" in text


def test_cli_dry_run(tmp_path: Path):
    md = tmp_path / "fixes.md"
    sh = tmp_path / "fix.sh"
    code = main(
        ["--from-json", str(SAMPLE), "--md", str(md), "--sh", str(sh), "--dry-run", "-q"]
    )
    assert code == 0
    assert not md.exists()
    assert not sh.exists()


def test_cli_ids():
    code = main(["--ids", "HOZ-SSH-001,HOZ-NET-006", "-q", "--stdout-md"])
    assert code == 0


def test_cli_requires_input():
    try:
        main([])
    except SystemExit as e:
        assert e.code == 2
        return
    raise AssertionError("esperaba SystemExit 2")


def test_fixture_matches_sample_shape():
    assert SAMPLE.is_file()
    data = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert "findings" in data
    assert data["hostname"] == "cliente-wp-07"
    assert FIXTURE.is_file()
