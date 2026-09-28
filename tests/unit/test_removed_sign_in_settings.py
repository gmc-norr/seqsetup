"""Sign-in settings that no longer do anything are warned about at start,
so their removal is never silent (spec 2026-09-28 group 2b)."""

import logging

from seqsetup.startup import warn_removed_sign_in_settings

BIND = ("SEQSETUP_LDAP_BIND_PASSWORD is set but no longer used: SeqSetup signs in to the "
        "directory as each user, not with a service account. Remove it.")
FILE = ("config/users.yaml is no longer read: sign-in with file accounts was removed. "
        "Make the first admin with 'pixi run create-admin'.")


class _Lines(logging.Handler):
    """Collects this logger's messages. Read here, not through caplog: the
    app's log scrubber may sit on pytest's shared handlers."""

    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class TestRemovedSignInSettings:
    """One warning per removed setting that is still present."""

    def test_bind_password_variable_is_warned(self, tmp_path):
        lines = _Lines()
        logger = logging.getLogger("seqsetup.startup")
        logger.addHandler(lines)
        try:
            said = warn_removed_sign_in_settings(
                {"SEQSETUP_LDAP_BIND_PASSWORD": "x"}, tmp_path / "users.yaml")
        finally:
            logger.removeHandler(lines)
        assert said == [BIND] and lines.lines == [BIND]

    def test_users_file_is_warned(self, tmp_path):
        users = tmp_path / "users.yaml"
        users.write_text("users: {}\n")
        assert warn_removed_sign_in_settings({}, users) == [FILE]

    def test_nothing_to_warn_about(self, tmp_path):
        assert warn_removed_sign_in_settings(
            {"SEQSETUP_LDAP_BIND_PASSWORD": ""}, tmp_path / "users.yaml") == []
