from __future__ import annotations

import re

from hozfix.model import FindingRef

_PATH_RE = re.compile(r"(/(?:[\w.$-]+/)*[\w.$-]+)")
_PORT_RE = re.compile(r":(\d+)\b")


class Ctx:
    def __init__(
        self,
        findings: list[FindingRef] | None = None,
        *,
        hostname: str = "",
    ) -> None:
        self.findings = list(findings or [])
        self._hostname = (hostname or "").strip()

    def by_id(self, fid: str) -> FindingRef | None:
        for f in self.findings:
            if f.id == fid:
                return f
        return None

    def hostname(self) -> str:
        if self._hostname:
            return self._hostname
        f = self.by_id("HOZ-HOST-001")
        if f and f.hallazgo:
            return f.hallazgo.split(",", 1)[0].strip()
        return ""

    def ssh_port(self) -> str:
        f = self.by_id("HOZ-SSH-005")
        if f:
            m = re.search(r"Port\s+(\d+)", f.hallazgo, re.I) or re.search(
                r"\b(\d{2,5})\b", f.hallazgo
            )
            if m:
                return m.group(1)
        for f in self.findings:
            if f.id.startswith("HOZ-SSH-") and f.evidencia:
                m = re.search(r"\bport\s+(\d+)", f.evidencia, re.I)
                if m:
                    return m.group(1)
        return "22"


def first_path(*texts: str) -> str | None:
    for text in texts:
        if not text:
            continue
        m = _PATH_RE.search(text)
        if m:
            return m.group(1)
    return None


def all_paths(*texts: str) -> list[str]:
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for p in _PATH_RE.findall(text):
            if p not in found:
                found.append(p)
    return found


def mysql_conf_path(f: FindingRef | None) -> str | None:
    if f is None:
        return None
    p = first_path(f.evidencia, f.hallazgo)
    if p and ("mysql" in p or "mariadb" in p or p.endswith(".cnf")):
        return p
    return None


def postgres_conf_path(f: FindingRef | None) -> str | None:
    if f is None:
        return None
    p = first_path(f.evidencia, f.hallazgo)
    if p and ("postgres" in p or p.endswith(".conf")):
        return p
    return None


def redis_conf_path(f: FindingRef | None) -> str | None:
    if f is None:
        return None
    p = first_path(f.evidencia, f.hallazgo)
    if p and ("redis" in p or p.endswith(".conf")):
        return p
    return None


def empty_password_users(f: FindingRef) -> list[str]:
    text = f"{f.hallazgo}\n{f.evidencia}"
    skip = {
        "uid", "root", "all", "yes", "no", "none", "user", "users", "cuenta",
        "cuentas", "sin", "password", "shadow", "empty", "passwd", "lock",
    }
    found: list[str] = []
    for part in re.split(r"[\s,;]+", text):
        part = part.strip().strip(":")
        if not part or part.lower() in skip:
            continue
        if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", part, re.I):
            if part not in found:
                found.append(part)
    return found[:20]


def docker_names(f: FindingRef) -> list[str]:
    names: list[str] = []
    for line in (f.evidencia or "").splitlines():
        line = line.strip()
        if not line:
            continue
        name = line.split("\t", 1)[0].strip().split()[0] if line.split() else ""
        low = name.lower()
        if not name or low in {"names", "container", "image", "ports", "status"}:
            continue
        if name not in names:
            names.append(name)
    return names[:10]


def listen_port(f: FindingRef, default: str | None = None) -> str | None:
    m = re.search(r"HOZ-NET-(\d{3})", f.id)
    port_by_id = {
        "001": "21", "002": "23", "003": "25", "004": "3306", "005": "5432",
        "006": "6379", "007": "27017", "008": "9200", "009": "2375", "010": "2376",
        "011": "8080", "012": "8443", "013": "10000", "014": "2082", "015": "2083",
        "016": "2086", "017": "2087",
    }
    if m and m.group(1) in port_by_id:
        return port_by_id[m.group(1)]
    for text in (f.evidencia, f.hallazgo):
        if not text:
            continue
        pm = _PORT_RE.search(text)
        if pm:
            return pm.group(1)
    return default


def systemd_units(f: FindingRef) -> list[str]:
    units: list[str] = []
    for text in (f.evidencia, f.hallazgo):
        if not text:
            continue
        for line in text.splitlines():
            token = line.strip().split()[0] if line.strip() else ""
            if token.endswith(".service") or token.endswith(".socket"):
                if token not in units:
                    units.append(token)
    return units[:15]
