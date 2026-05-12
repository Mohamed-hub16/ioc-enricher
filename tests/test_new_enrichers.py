"""Tests for the new enrichers added in PR #1."""

import pytest
from unittest.mock import patch, MagicMock
from src.models import IOC
from src.enrichers import shodan_internetdb, greynoise, urlhaus, threatfox, malwarebazaar


# ── Shodan InternetDB ──────────────────────────────────────────────────────────

def test_shodan_internetdb_ip_ok():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ports": [22, 80, 443],
        "hostnames": ["host.example.com"],
        "cpes": [],
        "vulns": ["CVE-2022-1234"],
        "tags": ["self-signed"],
    }
    with patch("httpx.get", return_value=mock_resp):
        result = shodan_internetdb.enrich(IOC(value="1.2.3.4", type="ip"))
    assert result.error is None
    assert result.data["found"] is True
    assert 22 in result.data["open_ports"]
    assert "CVE-2022-1234" in result.data["vulns"]


def test_shodan_internetdb_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("httpx.get", return_value=mock_resp):
        result = shodan_internetdb.enrich(IOC(value="1.2.3.4", type="ip"))
    assert result.error is None
    assert result.data["found"] is False


def test_shodan_internetdb_wrong_type():
    result = shodan_internetdb.enrich(IOC(value="example.com", type="domain"))
    assert result.error is not None


# ── GreyNoise ──────────────────────────────────────────────────────────────────

def test_greynoise_no_key():
    with patch.dict("os.environ", {}, clear=True):
        result = greynoise.enrich(IOC(value="1.2.3.4", type="ip"), keys={})
    assert result.error is not None


def test_greynoise_malicious():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "seen": True,
        "classification": "malicious",
        "noise": True,
        "riot": False,
        "name": "ShadowServer",
        "last_seen": "2024-01-15",
    }
    with patch("httpx.get", return_value=mock_resp):
        result = greynoise.enrich(
            IOC(value="1.2.3.4", type="ip"),
            keys={"GREYNOISE_API_KEY": "testkey"},
        )
    assert result.error is None
    assert result.data["classification"] == "malicious"


# ── URLhaus ────────────────────────────────────────────────────────────────────

def test_urlhaus_no_results():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "no_results"}
    with patch("httpx.post", return_value=mock_resp):
        result = urlhaus.enrich(IOC(value="1.2.3.4", type="ip"))
    assert result.error is None
    assert result.data["found"] is False


def test_urlhaus_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "is_host",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/1.2.3.4/",
        "url_count": 2,
        "blacklists": {"surbl": "not listed"},
        "urls": [
            {"url": "http://1.2.3.4/malware.exe", "url_status": "online", "threat": "malware_download", "date_added": "2024-01-01 00:00:00"},
        ],
    }
    with patch("httpx.post", return_value=mock_resp):
        result = urlhaus.enrich(IOC(value="1.2.3.4", type="ip"))
    assert result.error is None
    assert result.data["found"] is True
    assert result.data["url_count"] == 2


# ── ThreatFox ──────────────────────────────────────────────────────────────────

def test_threatfox_no_key():
    result = threatfox.enrich(IOC(value="1.2.3.4", type="ip"), keys={})
    assert result.error is not None


def test_threatfox_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [{
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware": "Win.Trojan.Cobalt-Strike",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 75,
            "first_seen": "2024-01-01 00:00:00",
        }],
    }
    with patch("httpx.post", return_value=mock_resp):
        result = threatfox.enrich(
            IOC(value="1.2.3.4", type="ip"),
            keys={"ABUSE_CH_API_KEY": "testkey"},
        )
    assert result.error is None
    assert result.data["found"] is True
    assert result.data["results"][0]["malware_printable"] == "Cobalt Strike"


# ── MalwareBazaar ──────────────────────────────────────────────────────────────

def test_malwarebazaar_wrong_type():
    result = malwarebazaar.enrich(IOC(value="1.2.3.4", type="ip"), keys={"ABUSE_CH_API_KEY": "k"})
    assert result.error is not None


def test_malwarebazaar_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "hash_not_found"}
    with patch("httpx.post", return_value=mock_resp):
        result = malwarebazaar.enrich(
            IOC(value="d41d8cd98f00b204e9800998ecf8427e", type="hash"),
            keys={"ABUSE_CH_API_KEY": "testkey"},
        )
    assert result.error is None
    assert result.data["found"] is False


def test_malwarebazaar_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [{
            "sha256_hash": "abc123" * 10 + "abcd",
            "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_name": "evil.exe",
            "signature": "Cobalt Strike",
            "file_size": 204800,
        }],
    }
    with patch("httpx.post", return_value=mock_resp):
        result = malwarebazaar.enrich(
            IOC(value="d41d8cd98f00b204e9800998ecf8427e", type="hash"),
            keys={"ABUSE_CH_API_KEY": "testkey"},
        )
    assert result.error is None
    assert result.data["found"] is True
    assert result.data["signature"] == "Cobalt Strike"
