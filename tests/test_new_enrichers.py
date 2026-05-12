"""Tests des nouveaux enrichers : Shodan InternetDB, GreyNoise, URLhaus,
ThreatFox, MalwareBazaar. Mocke httpx pour valider les contrats."""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from src.models import IOC
from src.enrichers import shodan_internetdb, greynoise, urlhaus, threatfox, malwarebazaar


def _mock_resp(status_code=200, payload=None):
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = payload or {}
    m.raise_for_status = MagicMock()
    return m


# ───────────────────────────── Shodan InternetDB ─────────────────────────────

def test_internetdb_unsupported_type():
    r = shodan_internetdb.enrich(IOC("evil.com", "domain"))
    assert not r.success and "Unsupported" in r.error


def test_internetdb_no_data():
    with patch("httpx.get", return_value=_mock_resp(status_code=404)):
        r = shodan_internetdb.enrich(IOC("1.2.3.4", "ip"))
    assert not r.success
    assert "No information" in r.error


def test_internetdb_success():
    payload = {"ports": [22, 80, 443], "vulns": ["CVE-2024-1"],
               "cpes": ["cpe:/a:apache:log4j"], "hostnames": ["x.example"],
               "tags": ["self-signed"]}
    with patch("httpx.get", return_value=_mock_resp(payload=payload)):
        r = shodan_internetdb.enrich(IOC("1.2.3.4", "ip"))
    assert r.success
    assert r.data["ports"] == [22, 80, 443]
    assert r.data["vulns"] == ["CVE-2024-1"]


# ──────────────────────────────── GreyNoise ───────────────────────────────────

def test_greynoise_missing_key(monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    r = greynoise.enrich(IOC("1.2.3.4", "ip"))
    assert not r.success and "not set" in r.error


def test_greynoise_riot(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "x")
    payload = {"ip": "8.8.8.8", "noise": False, "riot": True,
               "classification": "benign", "name": "Google Public DNS",
               "last_seen": "2026-05-01", "message": "ok"}
    with patch("httpx.get", return_value=_mock_resp(payload=payload)):
        r = greynoise.enrich(IOC("8.8.8.8", "ip"))
    assert r.success
    assert r.data["riot"] is True
    assert "RIOT" in r.data["verdict_short"]


def test_greynoise_noise(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "x")
    payload = {"ip": "1.1.1.1", "noise": True, "riot": False,
               "classification": "unknown", "last_seen": "2026-05-12"}
    with patch("httpx.get", return_value=_mock_resp(payload=payload)):
        r = greynoise.enrich(IOC("1.1.1.1", "ip"))
    assert r.success
    assert "Bruit Internet" in r.data["verdict_short"]


# ──────────────────────────────── URLhaus ─────────────────────────────────────

def test_urlhaus_missing_key(monkeypatch):
    monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
    r = urlhaus.enrich(IOC("evil.com", "domain"))
    assert not r.success and "not set" in r.error


def test_urlhaus_host_match(monkeypatch):
    monkeypatch.setenv("ABUSE_CH_API_KEY", "x")
    payload = {
        "query_status": "ok",
        "url_count": 3,
        "firstseen": "2026-01-01",
        "urls": [
            {"url": "http://evil.com/a", "url_status": "online",
             "dateadded": "2026-05-01", "threat": "malware_download",
             "tags": ["emotet"]},
        ],
        "blacklists": {"spamhaus_dbl": "listed"},
    }
    with patch("httpx.post", return_value=_mock_resp(payload=payload)):
        r = urlhaus.enrich(IOC("evil.com", "domain"))
    assert r.success
    assert r.data["online_url_count"] == 1
    assert "emotet" in r.data["tags"]


# ─────────────────────────────── ThreatFox ────────────────────────────────────

def test_threatfox_match(monkeypatch):
    monkeypatch.setenv("ABUSE_CH_API_KEY", "x")
    payload = {
        "query_status": "ok",
        "data": [
            {"ioc": "1.2.3.4", "ioc_type": "ip:port",
             "malware": "win.cobalt_strike", "malware_printable": "Cobalt Strike",
             "threat_type": "botnet_cc", "confidence_level": 90,
             "first_seen": "2026-04-01", "last_seen": "2026-05-10",
             "tags": ["cobaltstrike", "actor:fin7"]},
        ],
    }
    with patch("httpx.post", return_value=_mock_resp(payload=payload)):
        r = threatfox.enrich(IOC("1.2.3.4", "ip"))
    assert r.success
    assert "Cobalt Strike" in r.data["family_aliases"]
    assert r.data["max_confidence"] == 90


def test_threatfox_no_match(monkeypatch):
    monkeypatch.setenv("ABUSE_CH_API_KEY", "x")
    payload = {"query_status": "no_result"}
    with patch("httpx.post", return_value=_mock_resp(payload=payload)):
        r = threatfox.enrich(IOC("1.2.3.4", "ip"))
    assert not r.success


# ────────────────────────────── MalwareBazaar ─────────────────────────────────

def test_malwarebazaar_match(monkeypatch):
    monkeypatch.setenv("ABUSE_CH_API_KEY", "x")
    payload = {
        "query_status": "ok",
        "data": [{
            "sha256_hash": "a" * 64, "sha1_hash": "b" * 40, "md5_hash": "c" * 32,
            "file_name": "evil.exe", "file_type": "exe", "file_size": 12345,
            "signature": "Lockbit", "first_seen": "2026-01-01",
            "tags": ["ransomware", "lockbit"],
            "yara_rules": [{"rule_name": "lockbit_payload",
                            "description": "x", "author": "y"}],
            "vendor_intel": {"Triage": {"score": 10, "malware_family": "Lockbit"}},
            "intelligence": {"downloads": 5, "uploads": 1},
        }],
    }
    with patch("httpx.post", return_value=_mock_resp(payload=payload)):
        r = malwarebazaar.enrich(IOC("a" * 64, "hash"))
    assert r.success
    assert r.data["signature"] == "Lockbit"
    assert r.data["triage_family"] == "Lockbit"
    assert r.data["bazaar_reference"].startswith("https://bazaar.abuse.ch/sample/")


def test_malwarebazaar_not_found(monkeypatch):
    monkeypatch.setenv("ABUSE_CH_API_KEY", "x")
    payload = {"query_status": "hash_not_found"}
    with patch("httpx.post", return_value=_mock_resp(payload=payload)):
        r = malwarebazaar.enrich(IOC("0" * 64, "hash"))
    assert not r.success
