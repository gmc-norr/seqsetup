"""A stand-in for ``ldap3.Connection`` in sign-in tests (spec 2026-09-28 group 2b).

It holds passwords by bind name and answers each search by its exact
(search base, filter) pair, as a test registers it. Group membership is
therefore decided "by the server": SeqSetup's filter must match what the
test registered, and nothing SeqSetup compares on its own side can make it
match.

Like ldap3 (with its default ``raise_exceptions=False``), a search sets
``conn.result`` and does not raise when the server ends it with an error;
some entries can still come back (plan review 1, P1).

Use: ``monkeypatch.setattr(ldap3, "Connection", directory.connection)``.
"""

from ldap3.core.exceptions import LDAPSocketOpenError

# ldap3's names for the result codes these tests use.
_RESULT_NAMES = {0: "success", 4: "sizeLimitExceeded", 10: "referral",
                 50: "insufficientAccessRights"}

BASE = "dc=example,dc=org"
USERS = "cn=SeqSetup-Users,ou=groups,dc=example,dc=org"
ADMINS = "cn=SeqSetup-Admins,ou=groups,dc=example,dc=org"
AD_PATTERN = "{username}@lab.example.org"
LDAP_PATTERN = "uid={username},ou=people,dc=example,dc=org"
IN_CHAIN = "1.2.840.113556.1.4.1941"
PASSWORD = "Correct-Horse-7"


class FakeAttr:
    """An ldap3 attribute: ``.value`` and ``.values``."""

    def __init__(self, value):
        self.value = value
        if value is None:
            self.values = []
        else:
            self.values = list(value) if isinstance(value, list) else [value]


class FakeEntry:
    """An ldap3 entry: ``.entry_dn`` and one attribute per name."""

    def __init__(self, dn, attrs=None):
        self.entry_dn = dn
        for name, value in (attrs or {}).items():
            setattr(self, name, FakeAttr(value))


class FakeDirectory:
    """Configure accounts and answers, then patch ldap3.Connection with ``connection``."""

    def __init__(self):
        self.passwords = {}       # bind name -> password
        self.answers = {}         # (search base, filter) -> ([FakeEntry], result code)
        self.connections = []     # the keyword arguments of every connection made
        self.log = []             # ("open",), ("bind", user), ("search", base, filter, scope), ("unbind",)
        self.unreachable = False

    def answer(self, base, search_filter, *entries, result=0):
        """Register a search's entries and the result code the server ends it with."""
        self.answers[(base, search_filter)] = (list(entries), result)

    def connection(self, server, user=None, password=None, **kwargs):
        self.connections.append({"server": server, "user": user, "password": password, **kwargs})
        return _FakeConnection(self, user, password)


class _FakeConnection:
    def __init__(self, directory, user, password):
        self._directory = directory
        self._user = user
        self._password = password
        self.entries = []
        self.result = None

    def _reach(self):
        if self._directory.unreachable:
            raise LDAPSocketOpenError(
                "socket connection error while opening: [Errno 111] Connection refused")

    def open(self, *args, **kwargs):
        self._reach()
        self._directory.log.append(("open",))

    def bind(self):
        self._reach()
        self._directory.log.append(("bind", self._user))
        return bool(self._password) and self._directory.passwords.get(self._user) == self._password

    def search(self, search_base, search_filter, search_scope=None, attributes=None, **kwargs):
        self._directory.log.append(("search", search_base, search_filter, search_scope))
        entries, code = self._directory.answers.get((search_base, search_filter), ([], 0))
        self.entries = list(entries)
        self.result = {"result": code, "description": _RESULT_NAMES[code],
                       "type": "searchResDone"}
        # As ldap3: True when anything came back, whatever the result code.
        return bool(self.entries)

    def unbind(self):
        self._directory.log.append(("unbind",))


def ad_account(directory, name="anna", groups=(USERS,), display_name="Anna Svensson",
               email="anna@example.org", password=PASSWORD):
    """An Active Directory account; returns its UPN."""
    upn = f"{name}@lab.example.org"
    directory.passwords[upn] = password
    entry_dn = f"cn={name},ou=staff,{BASE}"
    directory.answer(BASE, f"(userPrincipalName={upn})",
                     FakeEntry(entry_dn, {"displayName": display_name, "mail": email}))
    for group in groups:
        directory.answer(BASE, f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:={group}))",
                         FakeEntry(entry_dn))
    return upn


def ldap_account(directory, name="anna", groups=(USERS,), display_name="Anna Svensson",
                 email="anna@example.org", password=PASSWORD, member_of_listed=None):
    """An LDAP account below BASE; returns its DN. ``member_of_listed`` puts
    a memberOf list on the entry itself (which SeqSetup must not trust)."""
    dn = f"uid={name},ou=people,{BASE}"
    directory.passwords[dn] = password
    attrs = {"displayName": display_name, "mail": email}
    if member_of_listed is not None:
        attrs["memberOf"] = member_of_listed
    directory.answer(dn, "(objectClass=*)", FakeEntry(dn, attrs))
    for group in groups:
        directory.answer(dn, f"(memberOf={group})", FakeEntry(dn))
    return dn


def use_directory(ctx, method=None, fallback=True, **ldap):
    """Turn directory sign-in on in a test app, fully set up."""
    from seqsetup.models.auth_config import AuthMethod, LDAPConfig

    method = method or AuthMethod.ACTIVE_DIRECTORY
    config = ctx.auth_config_repo.get()
    config.auth_method = method
    config.allow_local_fallback = fallback
    values = {"server_url": "ldaps://dc.example.org", "base_dn": BASE,
              "user_dn_pattern": AD_PATTERN if method is AuthMethod.ACTIVE_DIRECTORY else LDAP_PATTERN,
              "user_group_dn": USERS, "admin_group_dn": ADMINS}
    values.update(ldap)
    config.ldap_config = LDAPConfig(**values)
    ctx.auth_config_repo.save(config)
    return config
