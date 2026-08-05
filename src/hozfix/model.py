from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "info": 1,
    "skip": 0,
}

ACTIONABLE = frozenset({"critical", "high", "medium"})

# Menor = antes. Día 2: acceso SSH -> datos/servicios -> perímetro -> ruido/reboot.
PHASE = {
    "ssh": 10,
    "user": 15,
    "perm": 20,
    "db": 30,
    "docker": 35,
    "net": 40,
    "sudo": 45,
    "ufw": 50,
    "fail2ban": 60,
    "sysctl": 90,
    "systemd": 92,
    "updates": 95,
    "reboot": 99,
    "other": 100,
}


@dataclass
class FindingRef:
    id: str
    title: str = ""
    severity: str = "medium"
    hallazgo: str = ""
    evidencia: str = ""
    consejo: str = ""
    area: str = ""


@dataclass
class Fix:
    id: str
    title: str
    severity: str
    commands: list[str] = field(default_factory=list)
    note: str = ""
    hallazgo: str = ""
    evidencia: str = ""
    prerequisites: list[str] = field(default_factory=list)
    verify: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    phase: int = 100

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    @property
    def all_ids(self) -> list[str]:
        if self.source_ids:
            seen: list[str] = []
            for i in self.source_ids:
                if i not in seen:
                    seen.append(i)
            return seen
        return [self.id]

    @property
    def label(self) -> str:
        if self.id == "HOZ-SSH-BUNDLE":
            return self.id
        ids = self.all_ids
        if len(ids) > 1:
            return "+".join(ids)
        return self.id
