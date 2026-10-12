"""SEQSETUP_LIMS_ALLOWED_NETS names the networks a LIMS may live on.

``SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1`` used to switch off the whole
address check at once: it allowed loopback, every RFC1918 range, CGNAT —
and link-local, so a LIMS URL could reach ``169.254.169.254``, the cloud
instance metadata service, and read the host's own credentials. The
operator now lists the networks instead, and four kinds of address stay
refused however they are listed: link-local, multicast, unspecified and
reserved.
"""

import ipaddress
import socket

import pytest

from seqsetup.services import sample_api as mod
from seqsetup.services.sample_api import (
    LimsAllowedNetsError,
    SampleApiError,
    _validate_url,
    check_lims_allowed_nets,
    parse_allowed_nets,
)


ALLOWED = "SEQSETUP_LIMS_ALLOWED_NETS"
REMOVED = "SEQSETUP_LIMS_ALLOW_PRIVATE_NETS"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(ALLOWED, raising=False)
    monkeypatch.delenv(REMOVED, raising=False)
    monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_HTTP", raising=False)


def _stub_resolve(monkeypatch, ips):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 0)) for ip in ips]
    monkeypatch.setattr(mod.socket, "getaddrinfo", fake_getaddrinfo)


class TestTheListDecidesWhichPrivateAddressesAreAllowed:
    def test_a_listed_loopback_is_allowed(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "127.0.0.1/32")
        _stub_resolve(monkeypatch, ["127.0.0.1"])
        assert ipaddress.ip_address("127.0.0.1") in _validate_url("https://mock-lims.local/")

    def test_loopback_is_refused_when_it_is_not_listed(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "10.0.0.0/8")
        _stub_resolve(monkeypatch, ["127.0.0.1"])
        with pytest.raises(SampleApiError, match="loopback"):
            _validate_url("https://mock-lims.local/")

    def test_loopback_is_refused_with_no_list_at_all(self, monkeypatch):
        _stub_resolve(monkeypatch, ["127.0.0.1"])
        with pytest.raises(SampleApiError, match="loopback"):
            _validate_url("https://mock-lims.local/")

    def test_a_listed_corporate_network_is_allowed(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "10.0.0.0/8")
        _stub_resolve(monkeypatch, ["10.4.5.6"])
        assert _validate_url("https://lims.corp.example/") != []

    def test_a_private_address_outside_every_listed_network_is_refused(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "10.0.0.0/8")
        _stub_resolve(monkeypatch, ["192.168.1.7"])
        with pytest.raises(SampleApiError, match=ALLOWED):
            _validate_url("https://lims.corp.example/")

    def test_several_networks_can_be_listed(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "10.0.0.0/8, 192.168.0.0/16,172.16.0.0/12")
        for ip in ("10.1.1.1", "192.168.1.7", "172.20.0.9"):
            _stub_resolve(monkeypatch, [ip])
            assert _validate_url("https://lims.corp.example/") != []

    def test_a_public_address_needs_no_list(self, monkeypatch):
        _stub_resolve(monkeypatch, ["8.8.8.8"])
        assert ipaddress.ip_address("8.8.8.8") in _validate_url("https://lims.example.com/api")

    def test_one_private_address_among_several_still_refuses(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "10.0.0.0/8")
        _stub_resolve(monkeypatch, ["8.8.8.8", "192.168.1.7"])
        with pytest.raises(SampleApiError):
            _validate_url("https://mixed.example/")


class TestFourKindsOfAddressStayRefused:
    """Link-local, multicast, unspecified and reserved, however listed."""

    @pytest.mark.parametrize("net,ip", [
        ("169.254.0.0/16", "169.254.169.254"),   # cloud instance metadata
        ("169.254.169.254/32", "169.254.169.254"),
        ("224.0.0.0/4", "224.0.0.1"),
        ("240.0.0.0/4", "240.0.0.1"),
        ("0.0.0.0/32", "0.0.0.0"),
    ])
    def test_listing_one_does_not_allow_it(self, monkeypatch, net, ip):
        monkeypatch.setenv(ALLOWED, net)
        _stub_resolve(monkeypatch, [ip])
        with pytest.raises(SampleApiError):
            _validate_url("https://metadata.local/")

    def test_a_wide_network_does_not_let_the_metadata_address_through(self, monkeypatch):
        """The stricter reading: a /8 that merely contains a refused range is
        refused outright, so it can never carry one of its addresses."""
        monkeypatch.setenv(ALLOWED, "169.0.0.0/8")
        _stub_resolve(monkeypatch, ["169.254.169.254"])
        with pytest.raises(SampleApiError):
            _validate_url("https://metadata.local/")


class TestTheListIsCheckedBeforeTheAppStarts:
    def test_a_good_list_is_accepted(self):
        assert parse_allowed_nets("10.0.0.0/8, 127.0.0.1/32") == (
            ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.1/32"))

    def test_an_empty_list_is_no_networks(self):
        assert parse_allowed_nets("") == ()
        assert parse_allowed_nets(" , ") == ()

    @pytest.mark.parametrize("value", ["10.0.0.0/8/8", "not-a-network", "10.0.0.0/33",
                                       "10.0.0.5/8", "lims.example.com"])
    def test_a_value_that_is_not_cidr_is_refused(self, value):
        with pytest.raises(LimsAllowedNetsError, match="CIDR"):
            parse_allowed_nets(value)

    @pytest.mark.parametrize("value", ["169.254.0.0/16", "169.0.0.0/8", "0.0.0.0/0",
                                       "224.0.0.0/4", "240.0.0.0/4", "fe80::/10",
                                       "ff00::/8", "::/0"])
    def test_a_network_that_reaches_into_a_refused_range_is_refused(self, value):
        with pytest.raises(LimsAllowedNetsError, match="never"):
            parse_allowed_nets(value)

    def test_the_refusal_names_the_entry_and_what_it_overlaps(self):
        with pytest.raises(LimsAllowedNetsError) as refused:
            parse_allowed_nets("169.0.0.0/8")
        assert "169.0.0.0/8" in str(refused.value)
        assert "169.254.0.0/16" in str(refused.value)

    def test_a_bad_list_stops_the_start(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "169.254.0.0/16")
        with pytest.raises(RuntimeError, match=ALLOWED):
            check_lims_allowed_nets()

    def test_a_good_list_does_not_stop_the_start(self, monkeypatch):
        monkeypatch.setenv(ALLOWED, "10.0.0.0/8")
        check_lims_allowed_nets()

    def test_no_list_does_not_stop_the_start(self):
        check_lims_allowed_nets()


class TestTheOldVariableStopsTheStart:
    @pytest.mark.parametrize("value", ["1", "0", "", "true", "no"])
    def test_any_value_stops_the_start(self, monkeypatch, value):
        monkeypatch.setenv(REMOVED, value)
        with pytest.raises(RuntimeError) as stopped:
            check_lims_allowed_nets()
        assert REMOVED in str(stopped.value)
        assert ALLOWED in str(stopped.value)

    def test_it_no_longer_allows_anything(self, monkeypatch):
        """Set alone, it must not open a private range the way it used to."""
        monkeypatch.setenv(REMOVED, "1")
        _stub_resolve(monkeypatch, ["169.254.169.254"])
        with pytest.raises(SampleApiError):
            _validate_url("https://metadata.local/")


class TestTheRefusedRangesMatchPythonsOwnReading:
    """The start-up check compares a listed network with an explicit list of
    blocks; the request-time check asks ``ipaddress`` about the address. A
    block the explicit list is missing would let a listed network through."""

    def test_every_block_holds_only_never_allowed_addresses(self):
        for net in mod._NEVER_ALLOWED_NETS:
            for ip in (net.network_address, net.broadcast_address):
                assert mod._is_never_allowed_address(ip), f"{ip} in {net}"

    @pytest.mark.parametrize("ip", ["169.254.0.0", "169.254.255.255", "224.0.0.0",
                                    "239.255.255.255", "240.0.0.0", "255.255.255.255",
                                    "0.0.0.0", "fe80::", "ff02::1", "::", "::1", "100::1"])
    def test_every_never_allowed_address_is_inside_a_block(self, ip):
        address = ipaddress.ip_address(ip)
        assert mod._is_never_allowed_address(address)
        assert any(address in net for net in mod._NEVER_ALLOWED_NETS
                   if net.version == address.version)

    @pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "192.168.1.1", "8.8.8.8",
                                    "100.64.0.1", "172.16.0.1", "fc00::1"])
    def test_an_address_that_may_be_listed_is_not_in_a_block(self, ip):
        address = ipaddress.ip_address(ip)
        assert not mod._is_never_allowed_address(address)


class TestTheDeploymentSamplesDoNotSetTheRemovedVariable:
    """A deployment sample that still set ``SEQSETUP_LIMS_ALLOW_PRIVATE_NETS``
    would stop the app at start for every operator who copied it (the shape of
    TestDeploymentFilesDoNotAskForABindPassword)."""

    ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]

    @pytest.mark.parametrize("name", [".env.example", "docker-compose.yml"])
    def test_the_removed_variable_is_not_set(self, name):
        assert f"{REMOVED}=" not in (self.ROOT / name).read_text()

    @pytest.mark.parametrize("name", [".env.example"])
    def test_the_new_variable_is_offered(self, name):
        assert f"{ALLOWED}=" in (self.ROOT / name).read_text()


class TestTheAddressIsCheckedToo:
    """Two layers. The start-up check refuses a list that reaches into a
    never-allowed range, so the environment cannot produce one; the
    resolved address is checked as well, so no other way of supplying a
    network could carry a never-allowed address either."""

    def test_a_never_allowed_address_inside_a_listed_network_is_still_refused(
            self, monkeypatch):
        monkeypatch.setattr(mod, "parse_allowed_nets",
                            lambda value: (ipaddress.ip_network("169.254.0.0/16"),))
        _stub_resolve(monkeypatch, ["169.254.169.254"])

        with pytest.raises(SampleApiError, match="link-local, multicast"):
            _validate_url("https://metadata.local/")

    def test_a_listed_network_that_is_allowed_still_works_that_way(self, monkeypatch):
        """Control: the same bypass with an allowed network lets it through."""
        monkeypatch.setattr(mod, "parse_allowed_nets",
                            lambda value: (ipaddress.ip_network("10.0.0.0/8"),))
        _stub_resolve(monkeypatch, ["10.1.2.3"])

        assert _validate_url("https://lims.corp.example/") != []
