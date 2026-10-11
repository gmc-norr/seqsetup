"""The Docker Compose defaults fail closed (group 3a, N-08): the app's port
opens only on the server itself, and compose will not start without a
decision on HTTPS."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def _service(name):
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"][name]


class TestComposeDefaults:
    """docker-compose.yml as shipped (Docker is not needed to read it)."""

    def test_the_app_port_opens_only_on_the_server_by_default(self):
        assert _service("app")["ports"] == ["${SEQSETUP_PUBLISH_ADDRESS:-127.0.0.1}:5001:5001"]

    def test_https_only_must_be_set_in_env(self):
        settings = [e for e in _service("app")["environment"] if e.startswith("SEQSETUP_HTTPS_ONLY=")]
        assert settings == ["SEQSETUP_HTTPS_ONLY=${SEQSETUP_HTTPS_ONLY:?must set in .env}"]

    def test_mongodb_publishes_no_port(self):
        assert "ports" not in _service("mongodb")


class TestEnvExample:
    """.env.example, which an admin copies to .env."""

    def test_https_only_is_on(self):
        lines = (ROOT / ".env.example").read_text().splitlines()
        assert [l for l in lines if l.startswith("SEQSETUP_HTTPS_ONLY=")] == ["SEQSETUP_HTTPS_ONLY=1"]
