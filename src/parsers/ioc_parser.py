"""IOC parser — détection IP/domain/hash + refanging des entrées analystes.

Accepte des formats défanges courants utilisés dans les mails / Slack :
  - `hxxp://evil.com`     → `http://evil.com`
  - `8[.]8[.]8[.]8`        → `8.8.8.8`
  - `evil(.)example(.)com` → `evil.example.com`
  - `1[:]2[:]3[:]4`        → IPv6 partial (les `[:]` deviennent `:`)
  - `user[@]example.com`   → `user@example.com`
"""

import ipaddress
import re
from urllib.parse import urlparse

from src.models import IOC, IOCType

_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)


def refang(value: str) -> str:
    """Convertit une entrée défanges en valeur brute exploitable.
    Idempotent — n'altère pas une entrée déjà propre."""
    if not value:
        return value
    v = value.strip()
    # Schemes
    v = re.sub(r"^h[xX]{2,}p", "http", v, count=1)        # hxxp / hXXp → http
    v = re.sub(r"^h[xX]{2,}ps", "https", v, count=1)      # hxxps → https
    v = re.sub(r"^(https?)\[://\]", r"\1://", v, count=1, flags=re.IGNORECASE)
    v = re.sub(r"^(https?)\[:\]//", r"\1://", v, count=1, flags=re.IGNORECASE)
    # Defang `[.]`, `(.)`, `{.}` → `.`
    v = re.sub(r"\[\.\]", ".", v)
    v = re.sub(r"\(\.\)", ".", v)
    v = re.sub(r"\{\.\}", ".", v)
    v = v.replace("[dot]", ".").replace("(dot)", ".").replace("{dot}", ".")
    # Defang `[@]`, `(at)` → `@`
    v = re.sub(r"\[@\]", "@", v)
    v = re.sub(r"\(at\)", "@", v, flags=re.IGNORECASE)
    v = re.sub(r"\[at\]", "@", v, flags=re.IGNORECASE)
    # Defang `[:]` → `:`
    v = re.sub(r"\[:\]", ":", v)
    # Remove surrounding angles, quotes, backticks
    v = v.strip("<>\"'`")
    return v


def defang(value: str, ioc_type: IOCType | None = None) -> str:
    """Inverse de refang — pour les copy-paste dans mails/rapports.
    Pour les URL : remplace `http`/`https` par `hxxp`/`hxxps`. Pour les
    domaines/IP : `[.]` au lieu de `.`."""
    if not value:
        return value
    v = value
    if ioc_type == "ip":
        return v.replace(".", "[.]")
    if ioc_type == "domain":
        return v.replace(".", "[.]")
    if v.startswith("http://"):
        v = "hxxp://" + v[len("http://"):]
    elif v.startswith("https://"):
        v = "hxxps://" + v[len("https://"):]
    return v.replace(".", "[.]")


def _extract_host(url: str) -> str | None:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return parsed.hostname
    except Exception:
        return None


def detect_type(value: str) -> IOCType | None:
    """Identifie le type d'IOC. Renvoie None si non reconnu.
    Pour une URL : extrait l'hôte et le retourne en domaine ou IP."""
    v = value.strip()
    if not v:
        return None

    # Hash en premier (le plus rapide, pas d'ambiguïté)
    if _MD5.match(v) or _SHA1.match(v) or _SHA256.match(v):
        return "hash"

    # URL → on extrait l'hôte
    if _URL.match(v):
        host = _extract_host(v)
        return detect_type(host) if host else None

    # IP — utiliser ipaddress pour rejeter 999.999.999.999
    try:
        ip = ipaddress.ip_address(v)
        return "ip"  # supporte IPv4 et IPv6
    except ValueError:
        pass

    # Domaine
    if _DOMAIN.match(v):
        return "domain"

    return None


def parse_ioc_value(raw: str) -> tuple[str | None, IOCType | None]:
    """Refang + type detection. Renvoie (valeur normalisée, type) ou (None, None)."""
    if not raw:
        return None, None
    refanged = refang(raw)
    # Pour une URL on extrait l'hôte comme valeur stockée
    if _URL.match(refanged):
        host = _extract_host(refanged)
        if not host:
            return None, None
        # On retourne l'hôte (pas l'URL complète) — c'est ce qui est enrichi
        return host, detect_type(host)
    ioc_type = detect_type(refanged)
    return (refanged, ioc_type) if ioc_type else (None, None)


def parse_iocs(values: list[str]) -> tuple[list[IOC], list[str]]:
    """Return (valid IOCs, unrecognised values)."""
    iocs: list[IOC] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for raw in values:
        v = raw.strip()
        if not v or v.startswith("#"):
            continue
        normalized, ioc_type = parse_ioc_value(v)
        if normalized and ioc_type and normalized not in seen:
            seen.add(normalized)
            iocs.append(IOC(value=normalized, type=ioc_type))
        elif not ioc_type:
            unknown.append(v)
    return iocs, unknown


def parse_file(path: str) -> tuple[list[IOC], list[str]]:
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    return parse_iocs([line.strip() for line in lines])
