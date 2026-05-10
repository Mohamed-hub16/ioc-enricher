from unittest.mock import patch, MagicMock
from src.models import IOC
from src.enrichers.abuseipdb import enrich


def _make_ioc(value="1.2.3.4"):
    return IOC(value=value, type="ip")


def test_enrich_missing_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = enrich(_make_ioc())
    assert not result.success
    assert "not set" in result.error


def test_enrich_success(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 80,
            "countryCode": "DE",
            "isp": "Evil Corp",
            "domain": "evil.example.com",
            "totalReports": 42,
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
            "isWhitelisted": False,
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        result = enrich(_make_ioc())

    assert result.success
    assert result.data["abuse_confidence_score"] == 80
    assert result.data["country_code"] == "DE"
    assert result.data["total_reports"] == 42


def test_enrich_http_error(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")
    import httpx
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    error = httpx.HTTPStatusError("rate limited", request=MagicMock(), response=mock_resp)

    with patch("httpx.get", side_effect=error):
        result = enrich(_make_ioc())

    assert not result.success
    assert "429" in result.error
