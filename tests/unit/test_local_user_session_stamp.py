"""A database user's session stamp changes exactly when their role or
password changes, so logins made before the change stop working."""

from unittest.mock import patch

import bcrypt

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import User, UserRole
from seqsetup.services.auth import AuthService


def _user(**kw):
    return LocalUser(username="alice", display_name="Alice", **kw)


class TestSessionStamp:
    """The stamp is the database user's login generation."""

    def test_new_user_gets_a_random_stamp(self):
        a, b = _user(), _user()
        assert len(a.session_stamp) == 32 and a.session_stamp != b.session_stamp

    def test_stored_stamp_is_kept(self):
        u = _user()
        again = LocalUser.from_dict(u.to_dict())
        assert again.session_stamp == u.session_stamp

    def test_missing_stamp_reads_as_empty_every_time(self):
        doc = _user().to_dict()
        del doc["session_stamp"]
        assert LocalUser.from_dict(doc).session_stamp == ""
        assert LocalUser.from_dict(doc).session_stamp == ""

    def test_set_password_changes_the_stamp(self):
        u = _user()
        before = u.session_stamp
        u.set_password("Strong-Passw0rd!")
        assert u.session_stamp != before

    def test_role_change_changes_the_stamp(self):
        u = _user(role=UserRole.ADMIN)
        before = u.session_stamp
        u.role = UserRole.STANDARD
        assert u.session_stamp != before

    def test_same_role_name_and_email_keep_the_stamp(self):
        u = _user(role=UserRole.ADMIN)
        before = u.session_stamp
        u.role = UserRole.ADMIN
        u.display_name = "Alice B"
        u.email = "a@example.com"
        assert u.session_stamp == before


class TestLoginSource:
    """Each login knows which user source it came from."""

    def test_database_user_is_local_with_stamp(self):
        u = _user()
        user = u.to_user()
        assert (user.source, user.session_stamp) == ("local", u.session_stamp)

    def test_yaml_user_is_yaml(self, tmp_path):
        h = bcrypt.hashpw(b"Yaml-Passw0rd!", bcrypt.gensalt(rounds=4)).decode()
        cfg = tmp_path / "users.yaml"
        cfg.write_text(f"users:\n  bob:\n    password_hash: '{h}'\n    role: standard\n")
        user = AuthService(cfg).authenticate("bob", "Yaml-Passw0rd!")
        assert (user.source, user.session_stamp) == ("yaml", "")

    def test_ldap_user_is_ldap(self, tmp_path):
        class _Cfg:
            is_ldap_enabled = True
            allow_local_fallback = False
            ldap_config = object()

        plain = User(username="carol", display_name="Carol", role=UserRole.STANDARD)
        with patch("seqsetup.services.ldap.LDAPService") as svc:
            svc.return_value.authenticate.return_value = plain
            user = AuthService(tmp_path / "none.yaml",
                               get_auth_config=lambda: _Cfg()).authenticate("carol", "x")
        assert user.source == "ldap"
