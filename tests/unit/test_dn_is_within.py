"""_dn_is_within compares parsed DNs (spec 2026-09-28 group 2b, review P1)."""

import pytest

from seqsetup.services import ldap as ldap_module
from seqsetup.services.ldap import _dn_is_within

BASE = "dc=example,dc=org"


class TestDnIsWithin:
    """A DN is inside the base only when its last parsed components are the base's."""

    @pytest.mark.parametrize("dn, base, inside", [
        ("uid=anna,ou=people,dc=example,dc=org", BASE, True),
        ("UID=Anna, OU=People, DC=Example, DC=org", BASE, True),
        ("dc=example,dc=org", BASE, True),
        ("cn=SeqSetup\\, Admins,dc=example,dc=org", BASE, True),
        ("uid=x\\,dc=example,dc=org", BASE, False),
        ("uid=anna,ou=people,dc=other,dc=org", BASE, False),
        ("uid=anna,,dc=org", "dc=org", False),
        # "+" joins two values into one component; it is not a ","
        # (plan review 1, P2).
        ("uid=anna,ou=people,dc=example,dc=org", "ou=people+dc=example,dc=org", False),
        ("uid=anna,ou=people+dc=example,dc=org", "ou=people+dc=example,dc=org", True),
        ("uid=anna,ou=people+dc=example,dc=org", BASE, False),
    ])
    def test_inside_the_base(self, dn, base, inside):
        assert _dn_is_within(dn, base) is inside

    def test_string_normaliser_is_gone(self):
        # It made "cn=SeqSetup\, Admins" equal "cn=SeqSetup\,Admins" (review P1).
        assert not hasattr(ldap_module, "_normalize_dn")
