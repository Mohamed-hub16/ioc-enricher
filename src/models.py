from dataclasses import dataclass, field
from typing import Any, Literal

IOCType = Literal["ip", "domain", "hash"]


@dataclass
class IOC:
    value: str
    type: IOCType


@dataclass
class EnrichmentResult:
    source: str          # e.g. "AbuseIPDB"
    ioc: IOC
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None
