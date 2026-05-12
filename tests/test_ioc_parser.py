import pytest
from src.parsers.ioc_parser import detect_type, parse_iocs, refang, defang, parse_ioc_value


@pytest.mark.parametrize("value,expected", [
    ("1.2.3.4", "ip"),
    ("185.220.101.45", "ip"),
    ("2001:db8::1", "ip"),                       # IPv6
    ("::1", "ip"),                                # IPv6 loopback
    ("evil.example.com", "domain"),
    ("sub.evil.example.co.uk", "domain"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),
    ("http://evil.example.com/path", "domain"),   # URL → host
    ("https://1.2.3.4/", "ip"),                   # URL → IP
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


def test_detect_type_rejects_invalid_ip():
    assert detect_type("999.999.999.999") is None
    assert detect_type("256.1.1.1") is None


def test_detect_type_unknown():
    assert detect_type("not-an-ioc!!!") is None


@pytest.mark.parametrize("dirty,clean", [
    ("8[.]8[.]8[.]8",                     "8.8.8.8"),
    ("8(.)8(.)8(.)8",                     "8.8.8.8"),
    ("evil[.]example[.]com",              "evil.example.com"),
    ("hxxp://evil.example.com",           "http://evil.example.com"),
    ("hXXps://evil[.]example[.]com",      "https://evil.example.com"),
    ("user[@]example.com",                "user@example.com"),
    ("evil(dot)example(dot)com",          "evil.example.com"),
    ("https[:]//evil.com",                "https://evil.com"),
    ("\"1.2.3.4\"",                       "1.2.3.4"),
    ("`evil.com`",                        "evil.com"),
    ("evil.com",                          "evil.com"),   # idempotent
])
def test_refang(dirty, clean):
    assert refang(dirty) == clean


def test_defang_ip():
    assert defang("8.8.8.8", "ip") == "8[.]8[.]8[.]8"


def test_defang_domain():
    assert defang("evil.com", "domain") == "evil[.]com"


def test_parse_ioc_value_defanged():
    norm, t = parse_ioc_value("hxxps://evil[.]example[.]com/path")
    assert norm == "evil.example.com"
    assert t == "domain"


def test_parse_iocs_skips_comments_and_blanks():
    iocs, unknown = parse_iocs(["# comment", "", "  1.2.3.4  ", "bad??value"])
    assert len(iocs) == 1
    assert iocs[0].value == "1.2.3.4"
    assert unknown == ["bad??value"]


def test_parse_iocs_dedupe():
    """Le défanging peut produire des doublons (8.8.8.8 et 8[.]8[.]8[.]8 → même)."""
    iocs, _ = parse_iocs(["8.8.8.8", "8[.]8[.]8[.]8", "hxxp://8.8.8.8"])
    assert len(iocs) == 1


def test_parse_iocs_mixed():
    values = ["8.8.8.8", "google.com", "d41d8cd98f00b204e9800998ecf8427e",
              "hxxps://evil[.]com"]
    iocs, unknown = parse_iocs(values)
    assert len(iocs) == 4
    assert unknown == []
    types = {i.value: i.type for i in iocs}
    assert types["8.8.8.8"] == "ip"
    assert types["google.com"] == "domain"
    assert types["d41d8cd98f00b204e9800998ecf8427e"] == "hash"
    assert types["evil.com"] == "domain"
