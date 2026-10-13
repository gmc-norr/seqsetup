"""A forwarded address the limiter remembers a client by is cut to 64
characters (the night run's Q5, answered 2026-10-13).

Behind the proxy, the first X-Forwarded-For hop is text the client writes,
and it became a key in the sign-in limiter and the refusal counter with no
length limit: an 8 000-character value was kept whole. A real address is at
most 45 characters, so no real client changes bucket."""

from types import SimpleNamespace

import pytest

from seqsetup.rate_limit import client_identity


def _request(xff, host="10.0.0.9"):
    return SimpleNamespace(headers={"x-forwarded-for": xff} if xff else {},
                           client=SimpleNamespace(host=host))


@pytest.fixture
def behind_proxy(monkeypatch):
    monkeypatch.setenv("SEQSETUP_TRUST_FORWARDED_FOR", "1")


def test_a_long_forwarded_value_is_cut_to_64(behind_proxy):
    assert client_identity(_request("9" * 8000)) == "9" * 64


@pytest.mark.parametrize("address", [
    "203.0.113.7",
    "2001:db8:85a3:0:0:8a2e:370:7334",
    "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",  # 45 characters, the longest
])
def test_a_real_address_is_unchanged(behind_proxy, address):
    assert client_identity(_request(f"{address}, 10.0.0.1")) == address


def test_without_the_proxy_setting_the_tcp_address_is_used(monkeypatch):
    monkeypatch.delenv("SEQSETUP_TRUST_FORWARDED_FOR", raising=False)
    assert client_identity(_request("9" * 8000)) == "10.0.0.9"
