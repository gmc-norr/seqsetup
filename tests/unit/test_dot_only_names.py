"""A stored name made only of dots is refused at the model boundary.

A local username, or an index kit's name or version, of ``.`` or ``..`` can
be created but never removed, demoted or reset: the browser rewrites the URL
the app would need (``/admin/users/..`` becomes ``/admin/``,
``/indexes/kits/../1.0`` becomes ``/indexes/1.0``) and a percent-encoded one
is refused with 400 by the dot-segment guard in ``middleware.py`` before the
route runs. Only direct database access could undo it (security review
2026-10).

``...`` is not itself a dot segment, but one rule an operator can state
beats three special cases and no real name is only dots, so the rule is
"not made only of dots" for any length. It lives in each model, on
construction and on later assignment, so a direct attribute write from a
route handler cannot step around it.
"""

import pytest

from seqsetup.models.index import IndexKit, IndexMode
from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole

DOT_ONLY = [".", "..", "...", "." * 10, "." * 64]
# Names that only contain a dot, or none, and must behave exactly as before.
ORDINARY_NAMES = ["first.last", "a.b.c", ".hidden", "trailing.", "ops@lab",
                  "x", "a-1_2", "labadmin"]


class TestALocalUsernameMadeOnlyOfDots:
    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_it_cannot_be_constructed(self, name):
        with pytest.raises(ValueError, match="only of dots"):
            LocalUser(username=name, display_name="Dots", role=UserRole.ADMIN)

    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_it_cannot_be_assigned_to_a_user_that_already_exists(self, name):
        user = LocalUser(username="first.last", display_name="First Last")

        with pytest.raises(ValueError, match="only of dots"):
            user.username = name

        assert user.username == "first.last"

    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_it_cannot_be_loaded_from_a_stored_record(self, name):
        with pytest.raises(ValueError, match="only of dots"):
            LocalUser.from_dict(
                {"username": name, "display_name": "Dots", "role": "admin"})

    @pytest.mark.parametrize("name", ORDINARY_NAMES)
    def test_a_name_that_merely_holds_a_dot_is_untouched(self, name):
        assert LocalUser(username=name, display_name="d").username == name


def _kit(**kwargs) -> IndexKit:
    return IndexKit(index_mode=IndexMode.SINGLE, **kwargs)


class TestAnIndexKitNameOrVersionMadeOnlyOfDots:
    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_a_name_cannot_be_constructed(self, name):
        with pytest.raises(ValueError, match="only of dots"):
            _kit(name=name)

    @pytest.mark.parametrize("version", DOT_ONLY)
    def test_a_version_cannot_be_constructed(self, version):
        with pytest.raises(ValueError, match="only of dots"):
            _kit(name="Kit", version=version)

    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_a_name_cannot_be_assigned_to_a_kit_that_already_exists(self, name):
        kit = _kit(name="IDT.v2", version="1.0")

        with pytest.raises(ValueError, match="only of dots"):
            kit.name = name

        assert kit.name == "IDT.v2"

    @pytest.mark.parametrize("version", DOT_ONLY)
    def test_a_version_cannot_be_assigned_to_a_kit_that_already_exists(self, version):
        kit = _kit(name="IDT.v2", version="1.0")

        with pytest.raises(ValueError, match="only of dots"):
            kit.version = version

        assert kit.version == "1.0"

    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_a_name_cannot_be_loaded_from_a_stored_record(self, name):
        with pytest.raises(ValueError, match="only of dots"):
            IndexKit.from_dict({"name": name, "version": "1.0"})

    @pytest.mark.parametrize("version", DOT_ONLY)
    def test_a_version_cannot_be_loaded_from_a_stored_record(self, version):
        with pytest.raises(ValueError, match="only of dots"):
            IndexKit.from_dict({"name": "Kit", "version": version})

    @pytest.mark.parametrize("name", ["IDT.v2", "Kit 1.0", ".hidden", "xGen"])
    def test_a_name_that_merely_holds_a_dot_is_untouched(self, name):
        assert _kit(name=name).name == name

    @pytest.mark.parametrize("version", ["1.0", "1.0.2", "2", "v1.0-beta"])
    def test_a_version_that_merely_holds_a_dot_is_untouched(self, version):
        assert _kit(name="Kit", version=version).version == version

    def test_the_length_clamp_still_applies_to_an_ordinary_name(self):
        """The 256-character cap is unchanged; it just cannot produce a
        name of dots out of a longer one."""
        assert len(_kit(name="k" * 300).name) == 256
