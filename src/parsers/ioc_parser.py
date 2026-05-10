import re
from src.models import IOC, IOCType

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def detect_type(value: str) -> IOCType | None:
    if _IPV4.match(value):
        return "ip"
    if _MD5.match(value) or _SHA1.match(value) or _SHA256.match(value):
        return "hash"
    if _DOMAIN.match(value):
        return "domain"
    return None


def parse_iocs(values: list[str]) -> tuple[list[IOC], list[str]]:
    """Return (valid IOCs, unrecognised values)."""
    iocs: list[IOC] = []
    unknown: list[str] = []
    for raw in values:
        v = raw.strip()
        if not v or v.startswith("#"):
            continue
        ioc_type = detect_type(v)
        if ioc_type:
            iocs.append(IOC(value=v, type=ioc_type))
        else:
            unknown.append(v)
    return iocs, unknown


def parse_file(path: str) -> tuple[list[IOC], list[str]]:
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    return parse_iocs([line.strip() for line in lines])
