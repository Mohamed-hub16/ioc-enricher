import re
from urllib.parse import urlparse
from src.models import IOC, IOCType

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

# Common defang patterns to undo
_REFANG_MAP = [
    (re.compile(r"hxxps?", re.I), lambda m: m.group(0).replace("xx", "tt").replace("XX", "TT")),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\[\:\]"), ":"),
    (re.compile(r"\[at\]", re.I), "@"),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\\\."), "."),
]


def refang(value: str) -> str:
    """Reverse common defanging patterns."""
    for pattern, replacement in _REFANG_MAP:
        if callable(replacement):
            value = pattern.sub(replacement, value)
        else:
            value = pattern.sub(replacement, value)
    return value


def defang(value: str) -> str:
    """Apply defanging: replace dots and colons with safe equivalents."""
    return value.replace(".", "[.]").replace("://", "[://]")


def _extract_host(value: str) -> str:
    """If value looks like a URL, extract the hostname."""
    if value.startswith(("http://", "https://", "ftp://",
                         "hxxp://", "hxxps://", "hxxp[://]", "hxxps[://]")):
        try:
            parsed = urlparse(value)
            host = parsed.hostname or ""
            return host.strip("[]")  # strip IPv6 brackets
        except Exception:
            pass
    return value


def detect_type(value: str) -> IOCType | None:
    if _IPV4.match(value):
        return "ip"
    if _IPV6.match(value):
        return "ip"
    if _MD5.match(value) or _SHA1.match(value) or _SHA256.match(value):
        return "hash"
    if _DOMAIN.match(value):
        return "domain"
    return None


def parse_iocs(values: list[str]) -> tuple[list[IOC], list[str]]:
    """Return (valid IOCs, unrecognised values). Deduplicates preserving first-seen order."""
    iocs: list[IOC] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for raw in values:
        v = refang(raw.strip())
        v = _extract_host(v)
        if not v or v.startswith("#"):
            continue
        if v in seen:
            continue
        seen.add(v)
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
