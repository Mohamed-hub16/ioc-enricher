import pytest
from src.parsers.ioc_parser import detect_type, parse_iocs


@pytest.mark.parametrize("value,expected", [
    ("1.2.3.4", "ip"),
    ("185.220.101.45", "ip"),
    ("evil.example.com", "domain"),
    ("sub.evil.example.co.uk", "domain"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash"),   # MD5
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),  # SHA1
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),  # SHA256
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


def test_detect_type_unknown():
    assert detect_type("not-an-ioc!!!") is None


def test_parse_iocs_skips_comments_and_blanks():
    iocs, unknown = parse_iocs(["# comment", "", "  1.2.3.4  ", "bad??value"])
    assert len(iocs) == 1
    assert iocs[0].value == "1.2.3.4"
    assert unknown == ["bad??value"]


def test_parse_iocs_mixed():
    values = ["8.8.8.8", "google.com", "d41d8cd98f00b204e9800998ecf8427e"]
    iocs, unknown = parse_iocs(values)
    assert len(iocs) == 3
    assert unknown == []
    types = {i.value: i.type for i in iocs}
    assert types["8.8.8.8"] == "ip"
    assert types["google.com"] == "domain"
    assert types["d41d8cd98f00b204e9800998ecf8427e"] == "hash"
