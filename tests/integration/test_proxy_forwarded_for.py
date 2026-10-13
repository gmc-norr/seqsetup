"""Behind the documented nginx proxy, each user gets their own sign-in limit.

``client_identity`` takes the first ``X-Forwarded-For`` hop when
``SEQSETUP_TRUST_FORWARDED_FOR=1``, which is the real client only if the
proxy REPLACES the header. The example used
``$proxy_add_x_forwarded_for``, which appends to whatever the client sent,
so the first hop was a value the client chose: one browser could spend
every other user's sign-in attempts, or none of its own, by sending a new
name each time. The deployment recipe also never turned the variable on,
so every user behind the proxy shared one bucket -- the proxy's address --
and one person's typing locked out the whole lab.

The example now replaces the header, and the recipe turns the variable on.
Shaped after ``TestTheProxyExampleLetsTheBodiesThrough`` in
``tests/integration/test_body_limit.py``, which reads the same file.
"""

from types import SimpleNamespace


class TestTheProxyExampleReplacesTheForwardedForHeader:
    """The nginx example in docs/getting-started/deployment.rst."""

    def _example(self) -> str:
        from pathlib import Path

        guide = Path(__file__).resolve().parents[2] / "docs" / "getting-started" / "deployment.rst"
        return guide.read_text()

    def test_the_example_sets_the_header_to_the_real_client(self):
        import re

        found = re.findall(r"^       proxy_set_header X-Forwarded-For (\S+);",
                           self._example(), re.M)
        assert found == ["$remote_addr"]

    def test_the_example_does_not_append_to_what_the_client_sent(self):
        """The prose names ``$proxy_add_x_forwarded_for`` as the wrong choice,
        so only the directive itself is checked."""
        assert ("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for"
                not in self._example())

    def test_the_guide_turns_the_trust_variable_on(self):
        assert "SEQSETUP_TRUST_FORWARDED_FOR=1" in self._example()


class TestTheRecipeTurnsTheTrustVariableOn:
    """docker-compose.yml and .env.example, as shipped."""

    def _root(self):
        from pathlib import Path

        return Path(__file__).resolve().parents[2]

    def test_compose_passes_it_to_the_app_defaulting_to_on(self):
        import yaml

        service = yaml.safe_load((self._root() / "docker-compose.yml").read_text())
        settings = [e for e in service["services"]["app"]["environment"]
                    if e.startswith("SEQSETUP_TRUST_FORWARDED_FOR=")]
        assert settings == ["SEQSETUP_TRUST_FORWARDED_FOR=${SEQSETUP_TRUST_FORWARDED_FOR:-1}"]

    def test_env_example_sets_it_to_one(self):
        lines = (self._root() / ".env.example").read_text().splitlines()
        assert [l for l in lines if l.startswith("SEQSETUP_TRUST_FORWARDED_FOR=")] == [
            "SEQSETUP_TRUST_FORWARDED_FOR=1"]


class TestTwoUsersBehindThatProxyGetTwoBuckets:
    """What the example and the variable buy, read through the limiter."""

    @staticmethod
    def _request(forwarded_for: str, direct: str = "10.0.0.9"):
        return SimpleNamespace(headers={"x-forwarded-for": forwarded_for},
                               client=SimpleNamespace(host=direct))

    def test_the_identity_is_the_address_the_proxy_wrote(self, monkeypatch):
        from seqsetup.rate_limit import client_identity

        monkeypatch.setenv("SEQSETUP_TRUST_FORWARDED_FOR", "1")
        assert client_identity(self._request("203.0.113.7")) == "203.0.113.7"

    def test_two_clients_do_not_share_one_bucket(self, monkeypatch):
        from seqsetup.rate_limit import client_identity

        monkeypatch.setenv("SEQSETUP_TRUST_FORWARDED_FOR", "1")
        assert (client_identity(self._request("203.0.113.7"))
                != client_identity(self._request("203.0.113.8")))

    def test_without_the_variable_they_do(self, monkeypatch):
        """Why the recipe sets it: unset, every user is the proxy's address."""
        from seqsetup.rate_limit import client_identity

        monkeypatch.delenv("SEQSETUP_TRUST_FORWARDED_FOR", raising=False)
        assert (client_identity(self._request("203.0.113.7"))
                == client_identity(self._request("203.0.113.8"))
                == "10.0.0.9")
