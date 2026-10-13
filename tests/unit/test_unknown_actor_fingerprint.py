"""A name SeqSetup does not know becomes a marker and a KEYED fingerprint.

A refused sign-in used to store the typed name, so a password typed into
the name box was kept for ever and shown on Admin > Audit. A bare hash
would not fix that: an admin name, or a password from a known list, is
guessed by hashing candidates and comparing. The fingerprint is an HMAC
under a key derived from the session secret, so the same typed text groups
together within a deployment and cannot be matched from outside.
"""

import hashlib
import hmac

import pytest

from seqsetup.services import audit_log
from seqsetup.services.audit_log import (
    UNKNOWN_ACTOR,
    set_actor_fingerprint_secret,
    unknown_actor,
)


SECRET = "a" * 64
OTHER_SECRET = "b" * 64


@pytest.fixture(autouse=True)
def _keyed():
    """Each test starts from a known key and leaves none behind."""
    set_actor_fingerprint_secret(SECRET)
    yield
    set_actor_fingerprint_secret("")


class TestWhatIsStored:
    def test_it_starts_with_the_marker(self):
        assert unknown_actor("hunter2").startswith(UNKNOWN_ACTOR)

    def test_the_marker_says_the_name_is_not_known(self):
        assert UNKNOWN_ACTOR == "(unknown name)"

    def test_the_typed_text_is_not_in_it(self):
        assert "hunter2" not in unknown_actor("hunter2")

    def test_it_is_short(self):
        assert len(unknown_actor("hunter2")) <= len(UNKNOWN_ACTOR) + 9

    def test_the_fingerprint_is_hex(self):
        fingerprint = unknown_actor("hunter2").removeprefix(UNKNOWN_ACTOR).strip()
        assert fingerprint and all(c in "0123456789abcdef" for c in fingerprint)

    def test_a_very_long_typed_name_still_gives_a_short_actor(self):
        assert len(unknown_actor("x" * 5000)) <= len(UNKNOWN_ACTOR) + 9


class TestTheFingerprintGroupsRepeats:
    def test_the_same_text_gives_the_same_fingerprint(self):
        assert unknown_actor("hunter2") == unknown_actor("hunter2")

    def test_different_text_gives_a_different_fingerprint(self):
        assert unknown_actor("hunter2") != unknown_actor("hunter3")

    def test_an_empty_name_gets_its_own_group(self):
        assert unknown_actor("") != unknown_actor("hunter2")


class TestItIsKeyedNotABareHash:
    def test_a_bare_hash_of_the_text_is_not_the_fingerprint(self):
        """What makes trying candidates from outside useless."""
        bare = hashlib.sha256(b"hunter2").hexdigest()
        fingerprint = unknown_actor("hunter2").removeprefix(UNKNOWN_ACTOR).strip()
        assert not bare.startswith(fingerprint)

    def test_another_deployment_gets_another_fingerprint(self):
        mine = unknown_actor("hunter2")
        set_actor_fingerprint_secret(OTHER_SECRET)
        assert unknown_actor("hunter2") != mine

    def test_it_is_an_hmac_under_a_key_derived_from_the_secret(self):
        derived = hmac.new(SECRET.encode("utf-8"),
                           audit_log._FINGERPRINT_CONTEXT, hashlib.sha256).digest()
        expected = hmac.new(derived, b"hunter2", hashlib.sha256).hexdigest()
        fingerprint = unknown_actor("hunter2").removeprefix(UNKNOWN_ACTOR).strip()
        assert expected.startswith(fingerprint)

    def test_the_session_secret_is_not_the_key_and_is_not_kept(self):
        assert audit_log._fingerprint_key != SECRET.encode("utf-8")
        assert SECRET not in repr(vars(audit_log))

    def test_the_fingerprint_is_not_the_whole_digest(self):
        """A few hex characters: enough to group, too few to confirm a guess
        even for someone who later learns the key."""
        fingerprint = unknown_actor("hunter2").removeprefix(UNKNOWN_ACTOR).strip()
        assert len(fingerprint) < 64


class TestWithNoKeyThereIsNoFingerprint:
    def test_only_the_marker_is_stored(self):
        set_actor_fingerprint_secret("")
        assert unknown_actor("hunter2") == UNKNOWN_ACTOR
