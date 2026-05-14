"""
Shared logic for extracting a malware family name or tool/software label
from VirusTotal enricher data.

Single source of truth — imported by groq_synthesizer, admin_routes, migrate_db.
"""

import re

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GENERIC_SIGNERS = frozenset({
    "microsoft windows", "microsoft corporation", "windows", "verisign",
    "thawte", "digicert", "comodo", "sectigo", "globalsign", "entrust",
    "symantec", "certum", "ssl.com", "godaddy", "amazon",
})

_CORP_SUFFIXES = (
    " gmbh", " inc.", " inc", " llc", " ltd.", " ltd",
    " corp.", " corp", " corporation", " software", " s.a.", " s.r.o.",
    " ag", " bv", " oy", " ab",
)

# Substrings that indicate a certificate authority, not an end-entity
_CA_INDICATORS = (
    "certificate authority", "signing ca", "trusted root",
    "root ca", "intermediate", " ca ",
)

_INFRA_TAGS = frozenset({
    "tor", "vpn", "proxy", "cdn", "anonymizer", "i2p", "bulletproof",
})

_GENERIC_FILENAMES = frozenset({
    "setup", "installer", "install", "update", "updater", "client", "app",
    "application", "service", "agent", "server", "host", "launcher", "loader",
    "helper", "patch", "tool", "main", "x64", "x86", "client64", "client32",
    "svchost", "rundll32", "regsvr32", "wscript", "cscript", "mshta",
    "explorer", "taskhost", "taskeng", "conhost", "dllhost",
})

# GUID: 8-4-4-4-12 hex groups (separators optional or spaces)
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}[\s\-]?[0-9a-f]{4}[\s\-]?[0-9a-f]{4}"
    r"[\s\-]?[0-9a-f]{4}[\s\-]?[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Pure hex string (hash / random ID): only hex chars + optional separators, length ≥ 8
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F][0-9a-fA-F\-\s]*[0-9a-fA-F]$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_hex_like(s: str) -> bool:
    """Return True if *s* is a GUID, hash, or generic hex identifier."""
    if len(s) < 8:
        return False
    return bool(_GUID_RE.match(s) or _HEX_ONLY_RE.match(s))


def _fname_to_label(fname: str) -> str | None:
    """
    Derive a clean product label from a filename.

    Returns None for:
    - GUIDs / hex hashes used as filenames by VT (e.g. "202d6d80-86c9-…")
    - Generic utility names  (setup, installer, updater…)
    - Version-only residuals

    Examples:
        "AnyDesk.exe"                        → "AnyDesk"
        "anydesk-6-2-3.exe"                  → "Anydesk"
        "AnyDesk - 2021-04-28T103828.exe"    → "AnyDesk"
        "AnyDesk_Mediaconcept.exe"           → "AnyDesk"
        "202d6d80-86c9-4b3e-…"               → None   (GUID)
        "f9aefd3d984c….exe"                  → None   (hex)
        "setup.exe"                          → None   (generic)
    """
    if not fname:
        return None

    # 1. Strip file extension (.exe .dll .sys .msi …)
    base = re.sub(r"\.[a-zA-Z]{2,4}$", "", fname.strip())

    # 2. Reject GUIDs and hex strings before any further processing
    if _is_hex_like(base):
        return None

    # 3. Strip trailing version / date / copy-number suffixes
    name = re.sub(r"[-_\s]+v?\d[\d.\-]*$", "", base, flags=re.IGNORECASE).strip()
    name = re.sub(r"[-_\s]*\(\d+\)$", "", name).strip()
    name = re.sub(r"[-_\s]+\d{4}[-T\d.]+.*$", "", name).strip()

    # 4. Normalise separators → spaces, then take first word only
    #    ("AnyDesk Mediaconcept" → "AnyDesk", avoids custom-deployment noise)
    name = name.replace("-", " ").replace("_", " ").strip()
    first_word = name.split()[0] if name.split() else ""

    # 5. Final validation
    if len(first_word) <= 2:
        return None
    if first_word.lower() in _GENERIC_FILENAMES:
        return None
    if _is_hex_like(first_word):
        return None

    # Capitalise first letter while preserving existing mixed-case (AnyDesk, WinRAR…)
    return first_word[0].upper() + first_word[1:]


def _strip_corp_suffix(name: str) -> str:
    """Remove common corporate legal suffixes (two passes to handle 'philandro Software GmbH')."""
    for _ in range(2):
        lower = name.lower()
        for sfx in _CORP_SUFFIXES:
            if lower.endswith(sfx):
                name = name[: len(name) - len(sfx)].strip()
                break
    return name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_label(
    vt_data: dict | None,
    extra_sources: list[dict] | None = None,
) -> str | None:
    """
    Extract a malware family name or tool/software identifier from enricher data.

    Parameters
    ----------
    vt_data
        The ``data`` dict from the VirusTotal enricher result (may be None).
    extra_sources
        List of raw dicts ``{"source": str, "data": dict, "error": …}``
        for ThreatFox / MalwareBazaar results.

    Priority order
    --------------
    1. VT ``popular_threat_label`` / ``popular_threat_classification``
       → authoritative malware classification for known malicious hashes
    2. ThreatFox / MalwareBazaar ``malware_printable`` / ``signature``
       → real family names (may be blocked on cloud providers)
    3. VT ExifTool ``ProductName`` / ``InternalName``
       → most reliable for PE files that embed proper version resources
    4. VT file names: ``meaningful_name`` then ``names[]``
       → GUIDs and hex hashes filtered out, version suffixes stripped
    5. Certificate first non-CA signer (corporate suffix stripped)
       → fallback for signed software without ExifTool data
    6. Known infrastructure VT tags (tor, vpn, proxy, cdn…)
       → for IPs / domains
    """
    # ── 1. VT malware classification ────────────────────────────────────────
    if vt_data:
        label = vt_data.get("popular_threat_label")
        if label:
            return label
        ptc = vt_data.get("popular_threat_classification")
        if isinstance(ptc, dict) and ptc.get("label"):
            return ptc["label"]

    # ── 2. ThreatFox / MalwareBazaar ────────────────────────────────────────
    for src in extra_sources or []:
        data = src.get("data") if isinstance(src, dict) else None
        if not data or src.get("error"):
            continue
        items = data.get("results") or []
        family = (
            (items[0].get("malware_printable") or items[0].get("malware"))
            if items and isinstance(items, list)
            else data.get("signature")
        )
        if family:
            return family

    if not vt_data:
        return None

    # ── 3. ExifTool ProductName / InternalName ───────────────────────────────
    exif = vt_data.get("exiftool") or {}
    product = (exif.get("ProductName") or exif.get("InternalName") or "").strip()
    if product and len(product) > 2:
        return product

    # ── 4. File names (GUIDs / hex hashes automatically rejected) ───────────
    names_to_try: list[str] = []
    if vt_data.get("meaningful_name"):
        names_to_try.append(vt_data["meaningful_name"])
    names_to_try.extend(vt_data.get("names") or [])

    for fname in names_to_try:
        label = _fname_to_label(fname)
        if label:
            return label

    # ── 5. Certificate — first non-CA signer ────────────────────────────────
    sig = vt_data.get("signature_info") or {}
    for raw_signer in (sig.get("signers") or "").split(";"):
        signer = raw_signer.strip()
        if not signer:
            continue
        lower = signer.lower()
        # Skip certificate authorities
        if any(ind in lower for ind in _CA_INDICATORS):
            continue
        if lower in _GENERIC_SIGNERS:
            continue
        signer = _strip_corp_suffix(signer)
        lower = signer.lower()
        if not signer or len(signer) <= 3 or lower in _GENERIC_SIGNERS:
            continue
        return signer

    # ── 6. Infrastructure VT tags ────────────────────────────────────────────
    for tag in vt_data.get("tags") or []:
        if tag and tag.lower() in _INFRA_TAGS:
            return tag.lower()

    return None
