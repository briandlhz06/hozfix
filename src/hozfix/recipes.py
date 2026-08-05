from __future__ import annotations

import re

from hozfix.ctx import (
    Ctx,
    all_paths,
    docker_names,
    empty_password_users,
    first_path,
    listen_port,
    mysql_conf_path,
    postgres_conf_path,
    redis_conf_path,
    systemd_units,
)
from hozfix.model import PHASE, FindingRef, Fix, SEVERITY_RANK


def _fix(
    f: FindingRef,
    title: str,
    commands: list[str],
    *,
    note: str = "",
    prerequisites: list[str] | None = None,
    verify: list[str] | None = None,
    warnings: list[str] | None = None,
    phase: int = 100,
    source_ids: list[str] | None = None,
) -> Fix:
    return Fix(
        id=f.id,
        title=f.title or title,
        severity=f.severity or "medium",
        commands=commands,
        note=note or f.consejo,
        hallazgo=f.hallazgo,
        evidencia=f.evidencia,
        prerequisites=prerequisites or [],
        verify=verify or [],
        warnings=warnings or [],
        source_ids=source_ids or [f.id],
        phase=phase,
    )


def _ssh_dropin(lines: list[str]) -> list[str]:
    body = "\n".join(lines) + "\n"
    path = "/etc/ssh/sshd_config.d/99-hozfix.conf"
    return [
        "sudo mkdir -p /etc/ssh/sshd_config.d",
        f"sudo tee {path} >/dev/null <<'EOF'\n{body}EOF",
        "sudo sshd -t",
        "sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh",
    ]


def _ssh_prereqs(ctx: Ctx | None = None) -> list[str]:
    host = ctx.hostname() if ctx else ""
    out = [
        "Entrá con un usuario sudo + key en OTRA sesión y dejala abierta.",
        "id && sudo -v",
        "whoami   # ese es USUARIO; no inventamos el user si no viene en el JSON",
    ]
    if host:
        out.append(f"Host del reporte: {host}")
        out.append(f"Probá desde otra máquina: ssh -o BatchMode=yes USUARIO@{host} true")
    else:
        out.append("hostname -I | awk '{print $1}'")
        out.append("curl -4 -fsS ifconfig.me 2>/dev/null || true   # IP pública si hace falta")
        out.append(
            "Probá: ssh -o BatchMode=yes USUARIO@$(hostname -I | awk '{print $1}') true"
        )
    return out


def _ssh_verify() -> list[str]:
    return [
        "sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries'",
        "ls -la /etc/ssh/sshd_config.d/99-hozfix.conf",
    ]


def _ssh_warnings() -> list[str]:
    return [
        "LOCKOUT: si cortás root/password sin usuario sudo + key, te quedás afuera.",
    ]


def build_one(f: FindingRef, ctx: Ctx) -> Fix | None:
    fid = f.id
    ssh_port = ctx.ssh_port()

    if fid == "HOZ-SSH-001":
        return _fix(
            f,
            "Cortar root por SSH",
            _ssh_dropin(["PermitRootLogin no"]),
            note="Drop-in /etc/ssh/sshd_config.d/99-hozfix.conf (no toques el sshd_config principal).",
            prerequisites=_ssh_prereqs(ctx),
            verify=_ssh_verify(),
            warnings=_ssh_warnings(),
            phase=PHASE["ssh"],
        )
    if fid == "HOZ-SSH-002":
        return _fix(
            f,
            "Apagar login SSH con password",
            _ssh_dropin(["PasswordAuthentication no"]),
            note="Drop-in 99-hozfix.conf. Probá key en otra sesión antes.",
            prerequisites=_ssh_prereqs(ctx),
            verify=_ssh_verify(),
            warnings=_ssh_warnings(),
            phase=PHASE["ssh"],
        )
    if fid == "HOZ-SSH-003":
        return _fix(
            f,
            "Habilitar PubkeyAuthentication",
            _ssh_dropin(["PubkeyAuthentication yes"]),
            prerequisites=_ssh_prereqs(ctx),
            verify=_ssh_verify(),
            phase=PHASE["ssh"],
        )
    if fid == "HOZ-SSH-004":
        return _fix(
            f,
            "Bajar MaxAuthTries",
            _ssh_dropin(["MaxAuthTries 4"]),
            verify=_ssh_verify(),
            phase=PHASE["ssh"],
        )

    if fid.startswith("HOZ-NET-"):
        return _net_fix(f, ctx, ssh_port)

    if fid in {"HOZ-FW-001", "HOZ-FW-002"}:
        return _fix(
            f,
            "Activar UFW con política sana" if fid == "HOZ-FW-001" else "Cerrar INPUT abierto con UFW",
            [
                "sudo ufw default deny incoming",
                "sudo ufw default allow outgoing",
                f"sudo ufw allow {ssh_port}/tcp comment 'ssh'",
                "sudo ufw allow 80/tcp",
                "sudo ufw allow 443/tcp",
                "sudo ufw --force enable",
                "sudo ufw status verbose",
            ],
            note=(
                f"Allow SSH en {ssh_port}/tcp (del reporte HOZ-SSH-005 si venía). "
                "Si tus apps usan otros puertos, agregalos ANTES del enable."
            ),
            prerequisites=[
                f"Confirmá acceso por el puerto {ssh_port} desde otra sesión.",
                f"sudo ufw status | grep -E '{ssh_port}|Status' || true",
            ],
            verify=[
                "sudo ufw status verbose",
                f"sudo ss -lntp | grep ':{ssh_port}' || true",
            ],
            warnings=[
                f"LOCKOUT: ufw --force enable sin allow {ssh_port}/tcp te corta el SSH.",
            ],
            phase=PHASE["ufw"],
        )

    if fid in {"HOZ-FW-003", "HOZ-AUTH-001"}:
        cmds = [
            "sudo apt-get update && sudo apt-get install -y fail2ban",
            "sudo systemctl enable --now fail2ban",
        ]
        if ssh_port != "22":
            cmds.extend(
                [
                    "sudo mkdir -p /etc/fail2ban/jail.d",
                    (
                        "sudo tee /etc/fail2ban/jail.d/sshd-hozfix.local >/dev/null <<'EOF'\n"
                        "[sshd]\n"
                        "enabled = true\n"
                        f"port = {ssh_port}\n"
                        "EOF"
                    ),
                    "sudo systemctl restart fail2ban",
                ]
            )
        cmds.append("sudo fail2ban-client status sshd || sudo fail2ban-client status")
        return _fix(
            f,
            "fail2ban jail sshd",
            cmds,
            note=f"Puerto SSH del reporte: {ssh_port}. Mejor combo: keys + PasswordAuthentication no.",
            verify=["sudo fail2ban-client status sshd || true"],
            phase=PHASE["fail2ban"],
        )

    if fid == "HOZ-DB-002":
        return _mysql_bind_fix(f, ctx, include_ufw=True)

    if fid == "HOZ-DOCK-001":
        return _fix(
            f,
            "Revisar Docker daemon",
            [
                "sudo systemctl status docker --no-pager",
                "sudo journalctl -u docker -n 50 --no-pager",
                "sudo systemctl start docker",
            ],
            note="Si falta permiso: sudo o grupo docker.",
            verify=["docker info >/dev/null && echo ok || echo fail"],
            phase=PHASE["docker"],
        )

    if fid.startswith("HOZ-DOCK-"):
        return _docker_fix(f)

    if fid == "HOZ-USR-001":
        return _fix(
            f,
            "Investigar UID 0 extra",
            [
                "getent passwd | awk -F: '$3==0 {print}'",
                "sudo awk -F: '$3==0 {print}' /etc/passwd",
            ],
            note="Cualquier cuenta además de root con UID 0: investigá. No borres a ciegas.",
            phase=PHASE["user"],
        )

    if fid == "HOZ-USR-003":
        users = empty_password_users(f)
        if users:
            cmds = [f"sudo passwd -l {u}" for u in users]
            cmds.append(
                "sudo awk -F: '($2==\"\" || $2==\"!\" || $2==\"*\") {print $1}' /etc/shadow 2>/dev/null | head"
            )
            note = "Lock de: " + ", ".join(users) + " (sacados del hallazgo)."
        else:
            cmds = [
                "sudo awk -F: '($2==\"\") {print $1}' /etc/shadow",
                "# sudo passwd -l USUARIO   # por cada cuenta vacía que liste el awk",
            ]
            note = "No vinieron nombres en el JSON. Listá shadow y lockeá a mano."
        return _fix(
            f,
            "Bloquear cuentas sin password",
            cmds,
            note=note,
            verify=["sudo awk -F: '($2==\"\") {print $1}' /etc/shadow || true"],
            phase=PHASE["user"],
        )

    if fid == "HOZ-USR-004":
        return _fix(
            f,
            "Revisar NOPASSWD en sudoers",
            [
                "sudo grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true",
                "sudo visudo -c",
            ],
            note="Si no hace falta, sacá NOPASSWD o limitá al binario. Editá con visudo.",
            phase=PHASE["sudo"],
        )

    if fid == "HOZ-UPD-001":
        return _fix(
            f,
            "Instalar unattended-upgrades",
            [
                "sudo apt-get update && sudo apt-get install -y unattended-upgrades",
                "sudo dpkg-reconfigure -plow unattended-upgrades",
            ],
            note="En RHEL: dnf install dnf-automatic.",
            phase=PHASE["updates"],
        )

    if fid == "HOZ-UPD-002":
        return _fix(
            f,
            "Reboot pendiente",
            [
                "cat /var/run/reboot-required 2>/dev/null || true",
                "cat /var/run/reboot-required.pkgs 2>/dev/null || true",
                "# sudo reboot",
            ],
            note="Agendá ventana. Descomentá el reboot cuando puedas.",
            phase=PHASE["reboot"],
        )

    if fid == "HOZ-CTL-002":
        return _fix(
            f,
            "Activar tcp_syncookies",
            [
                "sudo sysctl -w net.ipv4.tcp_syncookies=1",
                "echo 'net.ipv4.tcp_syncookies = 1' | sudo tee /etc/sysctl.d/99-hozfix-syncookies.conf",
                "sudo sysctl --system",
            ],
            verify=["sysctl net.ipv4.tcp_syncookies"],
            phase=PHASE["sysctl"],
        )

    if fid == "HOZ-SYS-001":
        units = systemd_units(f)
        cmds = [
            "systemctl --failed --no-pager",
            "journalctl -p err -b --no-pager | tail -n 80",
        ]
        for u in units:
            cmds.append(f"systemctl status {u} --no-pager || true")
        return _fix(
            f,
            "Units failed",
            cmds,
            note="systemctl status NOMBRE y journalctl -u NOMBRE sobre cada failed.",
            phase=PHASE["systemd"],
        )

    m = re.fullmatch(r"HOZ-SYS-(.+)", fid)
    if m and m.group(1) not in {"000", "001"}:
        svc = m.group(1)
        if re.fullmatch(r"[A-Za-z0-9:_.\\-]+", svc):
            return _fix(
                f,
                f"Servicio {svc}",
                [
                    f"systemctl status {svc} --no-pager",
                    f"journalctl -u {svc} -n 80 --no-pager",
                    f"sudo systemctl restart {svc}",
                ],
                note="Solo restart si sabés que es seguro.",
                warnings=[f"Restart de {svc} puede cortar servicio en prod."],
                verify=[f"systemctl is-active {svc}"],
                phase=PHASE["systemd"],
            )

    if fid == "HOZ-CRON-001":
        return _fix(
            f,
            "Cron con curl/wget raro",
            [
                "sudo grep -RniE 'curl|wget|bash -i|/dev/tcp' /etc/cron* /var/spool/cron 2>/dev/null | head -n 50",
                "ls -la /etc/cron.d /etc/cron.daily /var/spool/cron/crontabs 2>/dev/null || true",
            ],
            note="Si no es tuyo: sacá la línea, rotá secrets, mirá procesos y listeners.",
            phase=PHASE["perm"],
        )

    if fid == "HOZ-CRON-002":
        paths = all_paths(f.evidencia, f.hallazgo)
        if paths:
            cmds: list[str] = []
            for p in paths:
                cmds.append(f"sudo chmod o-w {p}")
                cmds.append(f"sudo ls -la {p}")
            note = "Scripts del hallazgo: " + ", ".join(paths)
            verify = [f"ls -la {p}" for p in paths]
        else:
            cmds = [
                "sudo find /etc/cron* /var/spool/cron -type f -perm -002 2>/dev/null",
                "# sudo chmod o-w PATH && sudo ls -la PATH",
            ]
            note = "No vino path en el JSON. El find lista world-writable; chmod a mano."
            verify = []
        return _fix(
            f,
            "Scripts de cron world-writable",
            cmds,
            note=note,
            verify=verify,
            phase=PHASE["perm"],
        )

    wm = re.fullmatch(r"HOZ-WEB-(\d{3})", fid)
    if wm:
        return _web_fix(f, int(wm.group(1)))

    return None


def _mysql_bind_fix(
    f: FindingRef,
    ctx: Ctx,
    *,
    include_ufw: bool,
    extra_ids: list[str] | None = None,
) -> Fix:
    port = "3306"
    conf = mysql_conf_path(f) or mysql_conf_path(ctx.by_id("HOZ-DB-002"))
    cmds: list[str] = []
    if include_ufw:
        cmds.append(f"sudo ufw deny {port}/tcp || true")
    if conf:
        cmds.append(f"sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' {conf}")
        cmds.append(f"grep -n bind-address {conf} || true")
        note = f"Editando {conf} (path del hallazgo)."
    else:
        cmds.extend(
            [
                "sudo grep -Rns '^bind-address' /etc/mysql/ /etc/my.cnf /etc/my.cnf.d/ 2>/dev/null || true",
                "# No vino path en el JSON. Cuando lo encuentres:",
                "# sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' PATH.cnf",
            ]
        )
        note = "Sin path de conf en el reporte: discovery primero, después el sed."
    cmds.append(
        "sudo systemctl restart mysql 2>/dev/null || sudo systemctl restart mariadb 2>/dev/null || true"
    )
    cmds.append(f"sudo ss -lntp | grep ':{port}' || true")
    sources = extra_ids or [f.id]
    title = "MySQL/MariaDB a localhost"
    if include_ufw and "HOZ-NET-004" in sources:
        title = "Sacar MySQL/MariaDB de internet (bind + ufw)"
    return _fix(
        f,
        title,
        cmds,
        note=note + " Si hay clientes remotos, túnel o allowlist.",
        verify=[
            f"sudo ss -lntp | grep ':{port}' || true",
            f"grep -n bind-address {conf} || true" if conf else "sudo ss -lntp | grep 3306 || true",
        ],
        warnings=["Restart de MySQL/MariaDB corta conexiones activas."],
        phase=PHASE["db"],
        source_ids=sources,
    )


def _net_fix(f: FindingRef, ctx: Ctx, _ssh_port: str) -> Fix | None:
    fid = f.id
    port = listen_port(f)
    if not port:
        return None

    if fid == "HOZ-NET-004":
        return _mysql_bind_fix(
            f,
            ctx,
            include_ufw=True,
            extra_ids=["HOZ-NET-004"],
        )

    if fid == "HOZ-NET-005":
        conf = postgres_conf_path(f) or postgres_conf_path(ctx.by_id("HOZ-DB-003"))
        cmds = [f"sudo ufw deny {port}/tcp || true"]
        if conf:
            cmds.append(
                f"sudo sed -i \"s/^#\\?listen_addresses.*/listen_addresses = 'localhost'/\" {conf}"
            )
            cmds.append(f"grep -n listen_addresses {conf} || true")
            note = f"Editando {conf}."
        else:
            cmds.extend(
                [
                    "sudo grep -Rns '^listen_addresses' /etc/postgresql/ 2>/dev/null || true",
                    "# sudo sed -i \"s/^#\\?listen_addresses.*/listen_addresses = 'localhost'/\" PATH/postgresql.conf",
                ]
            )
            note = "Sin path en el reporte: discovery en /etc/postgresql/."
        cmds.append("sudo systemctl restart postgresql 2>/dev/null || true")
        cmds.append(f"sudo ss -lntp | grep ':{port}' || true")
        return _fix(
            f,
            "Sacar PostgreSQL de internet",
            cmds,
            note=note + " Revisá pg_hba.conf si hace falta acceso remoto controlado.",
            verify=[f"sudo ss -lntp | grep ':{port}' || true"],
            warnings=["Restart de PostgreSQL corta conexiones."],
            phase=PHASE["db"],
        )

    if fid == "HOZ-NET-006":
        conf = redis_conf_path(f)
        cmds = [f"sudo ufw deny {port}/tcp || true"]
        if conf:
            cmds.append(f"sudo sed -i 's/^bind .*/bind 127.0.0.1 ::1/' {conf}")
            cmds.append(f"sudo sed -i 's/^protected-mode .*/protected-mode yes/' {conf}")
            cmds.append(f"grep -nE '^(bind|protected-mode)' {conf} || true")
            note = f"Editando {conf}."
        else:
            cmds.extend(
                [
                    "sudo grep -RnsE '^(bind|protected-mode)' /etc/redis/ 2>/dev/null || true",
                    "# sudo sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf",
                    "# sudo sed -i 's/^protected-mode .*/protected-mode yes/' /etc/redis/redis.conf",
                ]
            )
            note = "Sin path en el reporte: discovery en /etc/redis/."
        cmds.append(
            "sudo systemctl restart redis-server 2>/dev/null || sudo systemctl restart redis 2>/dev/null || true"
        )
        cmds.append(f"sudo ss -lntp | grep ':{port}' || true")
        return _fix(
            f,
            "Cerrar Redis público",
            cmds,
            note=note + " Urgente. Si no hay requirepass, poné uno.",
            verify=[f"sudo ss -lntp | grep ':{port}' || true"],
            warnings=["Restart de Redis corta clientes."],
            phase=PHASE["db"],
        )

    if fid == "HOZ-NET-009":
        return _fix(
            f,
            "Cerrar Docker API sin TLS",
            [
                f"sudo ufw deny {port}/tcp || true",
                "sudo systemctl stop docker 2>/dev/null || true",
                f"sudo ss -lntp | grep ':{port}' || true",
            ],
            note="2375 abierto = control del host. Sacalo.",
            verify=[f"sudo ss -lntp | grep ':{port}' || true"],
            warnings=["Stop de docker tumba contenedores."],
            phase=PHASE["net"],
        )

    titles = {
        "HOZ-NET-001": "Cerrar FTP público",
        "HOZ-NET-002": "Apagar Telnet",
        "HOZ-NET-003": "Acotar SMTP afuera",
        "HOZ-NET-007": "Cerrar MongoDB público",
        "HOZ-NET-008": "Cerrar Elasticsearch público",
        "HOZ-NET-010": "Revisar Docker API TLS",
        "HOZ-NET-011": "Revisar servicio en 8080",
        "HOZ-NET-012": "Revisar servicio en 8443",
        "HOZ-NET-013": "Acotar Webmin",
        "HOZ-NET-014": "Acotar cPanel",
        "HOZ-NET-015": "Acotar cPanel SSL",
        "HOZ-NET-016": "Acotar WHM",
        "HOZ-NET-017": "Acotar WHM SSL",
    }
    cmds = [
        f"sudo ss -lntp | grep ':{port}' || true",
        f"sudo ufw deny {port}/tcp || true",
    ]
    if fid == "HOZ-NET-001":
        cmds.append(
            "sudo systemctl disable --now vsftpd 2>/dev/null || sudo systemctl disable --now proftpd 2>/dev/null || true"
        )
    if fid == "HOZ-NET-002":
        cmds.append("sudo systemctl disable --now telnet.socket 2>/dev/null || true")
    note = f.consejo or f"Cerrá el puerto {port} al mundo si no tiene que estar público."
    return _fix(
        f,
        titles.get(fid, f"Acotar puerto {port}"),
        cmds,
        note=note,
        verify=[f"sudo ss -lntp | grep ':{port}' || true", "sudo ufw status | grep " + port + " || true"],
        phase=PHASE["net"],
    )


def _docker_fix(f: FindingRef) -> Fix:
    names = docker_names(f)
    mport = re.fullmatch(r"HOZ-DOCK-(3306|5432|6379|27017|2375)", f.id)
    port = mport.group(1) if mport else None
    cmds: list[str] = []
    if port:
        cmds.append(
            f"docker ps --filter publish={port} --format 'table {{{{.Names}}}}\\t{{{{.Ports}}}}'"
        )
    cmds.append("docker ps --format 'table {{.Names}}\\t{{.Ports}}\\t{{.Image}}'")
    if names:
        for n in names:
            cmds.append(
                f"docker inspect --format '{{{{.Name}}}} {{{{json .HostConfig.PortBindings}}}}' {n} 2>/dev/null || true"
            )
        note = (
            "Contenedores del hallazgo: "
            + ", ".join(names)
            + ". En compose: '127.0.0.1:HOST:CONT' y recreá."
        )
    elif port:
        note = f"Publish de {port} al mundo. Cambiá a 127.0.0.1:{port}:{port}."
    else:
        note = "En compose: ports con 127.0.0.1:HOST:CONT. Redeploy."
    if port == "2375":
        cmds.append("sudo ufw deny 2375/tcp || true")
    verify = []
    if names:
        verify = [f"docker port {n} 2>/dev/null || true" for n in names]
    return _fix(
        f,
        f.title or "Docker publish público",
        cmds,
        note=note,
        verify=verify,
        phase=PHASE["docker"],
    )


def _web_fix(f: FindingRef, n: int) -> Fix | None:
    path = first_path(f.evidencia, f.hallazgo)
    if 1 <= n <= 99:
        if path:
            cmds = [
                f"sudo chmod 600 {path}",
                f"sudo chown root:root {path} 2>/dev/null || true",
                f"ls -la {path}",
            ]
            note = f"Path del hallazgo: {path}. Mejor: sacalo del docroot."
            verify = [f"ls -la {path}", f"stat -c '%a %n' {path}"]
        else:
            cmds = [
                "sudo find /var/www /srv /home -name '.env' -type f 2>/dev/null | head",
                "# sudo chmod 600 PATH && ls -la PATH",
            ]
            note = "No vino path en el JSON. El find busca .env; chmod a mano."
            verify = []
        return _fix(
            f,
            ".env legible en docroot",
            cmds,
            note=note,
            verify=verify,
            phase=PHASE["perm"],
        )
    if 100 <= n <= 199:
        if path:
            cmds = [
                f"sudo chmod 640 {path}",
                f"sudo chown root:www-data {path} 2>/dev/null || sudo chown root:nginx {path} 2>/dev/null || true",
                f"ls -la {path}",
            ]
            note = f"Path: {path}."
            verify = [f"ls -la {path}"]
        else:
            cmds = [
                "sudo find /var/www /srv -name 'wp-config.php' 2>/dev/null | head",
                "# sudo chmod 640 PATH && ls -la PATH",
            ]
            note = "No vino path en el JSON. Buscá wp-config y chmod a mano."
            verify = []
        return _fix(
            f,
            "wp-config.php con permisos flojos",
            cmds,
            note=note,
            verify=verify,
            phase=PHASE["perm"],
        )
    if 200 <= n <= 299:
        if path:
            cmds = [f"sudo chmod o-w {path}", f"ls -ld {path}"]
            note = f"Path: {path}. Si el proceso web escribe, dueño www-data + 775, no o+w."
            verify = [f"ls -ld {path}"]
        else:
            cmds = [
                "sudo find /var/www /srv -type d -perm -002 2>/dev/null | head",
                "# sudo chmod o-w PATH && ls -ld PATH",
            ]
            note = "No vino path en el JSON. El find lista dirs o+w."
            verify = []
        return _fix(
            f,
            "Directorio world-writable",
            cmds,
            note=note,
            verify=verify,
            phase=PHASE["perm"],
        )
    return None


def coalesce_ssh(fixes: list[Fix], ctx: Ctx | None = None) -> list[Fix]:
    ssh_ids = {"HOZ-SSH-001", "HOZ-SSH-002", "HOZ-SSH-003", "HOZ-SSH-004"}
    present = [fx for fx in fixes if fx.id in ssh_ids]
    if len(present) < 2:
        return fixes

    lines: list[str] = []
    id_order = ["HOZ-SSH-001", "HOZ-SSH-002", "HOZ-SSH-003", "HOZ-SSH-004"]
    mapping = {
        "HOZ-SSH-001": "PermitRootLogin no",
        "HOZ-SSH-002": "PasswordAuthentication no",
        "HOZ-SSH-003": "PubkeyAuthentication yes",
        "HOZ-SSH-004": "MaxAuthTries 4",
    }
    titles: list[str] = []
    worst = "info"
    hallazgo_bits: list[str] = []
    for sid in id_order:
        for fx in present:
            if fx.id == sid:
                lines.append(mapping[sid])
                titles.append(fx.id)
                hallazgo_bits.append(fx.hallazgo or fx.title)
                if SEVERITY_RANK.get(fx.severity, 0) > SEVERITY_RANK.get(worst, 0):
                    worst = fx.severity
                break
    if not lines:
        return fixes

    merged = Fix(
        id="HOZ-SSH-BUNDLE",
        title="Endurecer SSH (drop-in)",
        severity=worst,
        commands=_ssh_dropin(lines),
        note=(
            "Un solo drop-in con: "
            + ", ".join(titles)
            + ". Archivo: /etc/ssh/sshd_config.d/99-hozfix.conf"
        ),
        hallazgo="; ".join(x for x in hallazgo_bits if x),
        evidencia="\n".join(lines),
        prerequisites=_ssh_prereqs(ctx),
        verify=_ssh_verify(),
        warnings=_ssh_warnings(),
        source_ids=titles,
        phase=PHASE["ssh"],
    )
    out = [fx for fx in fixes if fx.id not in ssh_ids]
    out.append(merged)
    return out


def dedupe_fixes(fixes: list[Fix]) -> list[Fix]:
    by_id = {fx.id: fx for fx in fixes}

    # NET-004 + DB-002 -> un solo bind+ufw
    if "HOZ-NET-004" in by_id and "HOZ-DB-002" in by_id:
        net = by_id["HOZ-NET-004"]
        db = by_id["HOZ-DB-002"]
        sources = ["HOZ-NET-004", "HOZ-DB-002"]
        worst = (
            net.severity
            if SEVERITY_RANK.get(net.severity, 0) >= SEVERITY_RANK.get(db.severity, 0)
            else db.severity
        )
        evidencia = db.evidencia or net.evidencia
        hallazgo = f"{net.hallazgo} | {db.hallazgo}".strip(" |")
        blob = "\n".join(net.commands)
        conf = mysql_conf_path(
            FindingRef(id="HOZ-DB-002", evidencia=db.evidencia, hallazgo=db.hallazgo)
        )
        if conf and conf not in blob:
            rebuilt = _mysql_bind_fix(
                FindingRef(
                    id="HOZ-NET-004",
                    title=net.title,
                    severity=worst,
                    hallazgo=hallazgo,
                    evidencia=evidencia,
                ),
                Ctx(),
                include_ufw=True,
                extra_ids=sources,
            )
            commands = rebuilt.commands
            verify = rebuilt.verify
            note = rebuilt.note + " Cubre HOZ-NET-004 + HOZ-DB-002."
            warnings = rebuilt.warnings
        else:
            commands = net.commands
            verify = net.verify
            note = net.note + " Cubre también HOZ-DB-002."
            warnings = net.warnings or db.warnings
        by_id["HOZ-NET-004"] = Fix(
            id="HOZ-NET-004",
            title="Sacar MySQL/MariaDB de internet (bind + ufw)",
            severity=worst,
            commands=commands,
            note=note,
            hallazgo=hallazgo,
            evidencia=evidencia,
            prerequisites=net.prerequisites,
            verify=verify,
            warnings=warnings,
            source_ids=sources,
            phase=PHASE["db"],
        )
        by_id.pop("HOZ-DB-002")

    # FW-003 + AUTH-001 -> un fail2ban
    if "HOZ-FW-003" in by_id and "HOZ-AUTH-001" in by_id:
        fw = by_id["HOZ-FW-003"]
        auth = by_id["HOZ-AUTH-001"]
        worst = fw.severity if SEVERITY_RANK.get(fw.severity, 0) >= SEVERITY_RANK.get(auth.severity, 0) else auth.severity
        by_id["HOZ-FW-003"] = Fix(
            id="HOZ-FW-003",
            title="fail2ban jail sshd",
            severity=worst,
            commands=fw.commands,
            note=fw.note + " Cubre también HOZ-AUTH-001 (fallos SSH).",
            hallazgo=f"{fw.hallazgo} | {auth.hallazgo}".strip(" |"),
            evidencia=(fw.evidencia or "") + (("\n" + auth.evidencia) if auth.evidencia else ""),
            prerequisites=fw.prerequisites,
            verify=fw.verify,
            warnings=fw.warnings,
            source_ids=["HOZ-FW-003", "HOZ-AUTH-001"],
            phase=PHASE["fail2ban"],
        )
        by_id.pop("HOZ-AUTH-001")

    # FW-001 + FW-002 ambos piden UFW enable -> uno
    if "HOZ-FW-001" in by_id and "HOZ-FW-002" in by_id:
        a = by_id["HOZ-FW-001"]
        b = by_id["HOZ-FW-002"]
        worst = a.severity if SEVERITY_RANK.get(a.severity, 0) >= SEVERITY_RANK.get(b.severity, 0) else b.severity
        by_id["HOZ-FW-001"] = Fix(
            id="HOZ-FW-001",
            title="Activar UFW con política sana",
            severity=worst,
            commands=a.commands,
            note=a.note + " Cubre también HOZ-FW-002.",
            hallazgo=f"{a.hallazgo} | {b.hallazgo}".strip(" |"),
            evidencia=a.evidencia or b.evidencia,
            prerequisites=a.prerequisites,
            verify=a.verify,
            warnings=a.warnings,
            source_ids=["HOZ-FW-001", "HOZ-FW-002"],
            phase=PHASE["ufw"],
        )
        by_id.pop("HOZ-FW-002")

    return list(by_id.values())


def order_fixes(fixes: list[Fix]) -> list[Fix]:
    return sorted(fixes, key=lambda x: (x.phase, -x.rank, x.id))


def lookup(fid: str) -> bool:
    if fid in {
        "HOZ-SSH-001", "HOZ-SSH-002", "HOZ-SSH-003", "HOZ-SSH-004",
        "HOZ-FW-001", "HOZ-FW-002", "HOZ-FW-003", "HOZ-AUTH-001",
        "HOZ-DB-002", "HOZ-DOCK-001", "HOZ-USR-001", "HOZ-USR-003", "HOZ-USR-004",
        "HOZ-UPD-001", "HOZ-UPD-002", "HOZ-CTL-002", "HOZ-SYS-001",
        "HOZ-CRON-001", "HOZ-CRON-002",
        "HOZ-SSH-BUNDLE",
    }:
        return True
    if re.fullmatch(r"HOZ-NET-\d{3}", fid):
        return True
    if re.fullmatch(r"HOZ-DOCK-\d+", fid) or fid == "HOZ-DOCK-010":
        return True
    if re.fullmatch(r"HOZ-WEB-\d{3}", fid):
        return True
    if re.fullmatch(r"HOZ-SYS-.+", fid) and not fid.endswith("-000"):
        return True
    return False


def recipe_for(finding: FindingRef, ctx: Ctx | None = None) -> Fix | None:
    return build_one(finding, ctx or Ctx(findings=[finding]))
