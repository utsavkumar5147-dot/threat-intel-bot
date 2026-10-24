import pytest

from core.ioc_classifier import classify_ioc, classify_ip, normalize_domain


def test_public_ip():
    result = classify_ioc("8.8.8.8")
    assert result["valid"] is True
    assert result["type"] == "ip"
    assert result["classification"] == "public"
    assert result["external_lookup_allowed"] is True


def test_private_ip():
    result = classify_ioc("192.168.1.1")
    assert result["valid"] is True
    assert result["classification"] == "private_or_reserved"
    assert result["external_lookup_allowed"] is False


def test_loopback_ip():
    result = classify_ioc("127.0.0.1")
    assert result["classification"] == "loopback"
    assert result["external_lookup_allowed"] is False


def test_invalid_ip():
    assert classify_ip("999.999.999.999") is None


def test_domain_normalization():
    assert normalize_domain("EXAMPLE.COM.") == "example.com"


def test_domain_classification():
    result = classify_ioc("example.com")
    assert result["valid"] is True
    assert result["type"] == "domain"


def test_url_classification():
    result = classify_ioc("https://example.com/login")
    assert result["valid"] is True
    assert result["type"] == "url"
    assert result["host"] == "example.com"


def test_url_with_credentials_rejected():
    result = classify_ioc("https://user:password@example.com/")
    assert result["valid"] is False


def test_sha256_hash():
    result = classify_ioc("a" * 64)
    assert result["valid"] is True
    assert result["type"] == "sha256"


@pytest.mark.parametrize("value", [
    "",
    "   ",
    None,
    123,
    "example.com\nmalicious",
    "a" * 2049,
])
def test_invalid_inputs(value):
    assert classify_ioc(value)["valid"] is False
