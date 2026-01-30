"""Tests for PEP 440 version resolution."""

import pytest

from sequencing_run_setup.models.application_profile import ApplicationProfile
from sequencing_run_setup.models.test_profile import ApplicationProfileReference
from sequencing_run_setup.services.version_resolver import (
    resolve_application_profiles,
)


def _make_ap(name: str, version: str) -> ApplicationProfile:
    """Helper to create an ApplicationProfile with just name and version."""
    return ApplicationProfile(name=name, version=version, application_name=f"App_{name}")


def _make_ref(name: str, constraint: str) -> ApplicationProfileReference:
    """Helper to create an ApplicationProfileReference."""
    return ApplicationProfileReference(profile_name=name, profile_version=constraint)


class TestCompatibleRelease:
    """Tests for ~= (compatible release) constraints."""

    def test_compatible_release_matches_same_version(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [_make_ap("BCLConvert", "1.0.0")]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")] is profiles[0]

    def test_compatible_release_matches_higher_patch(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [
            _make_ap("BCLConvert", "1.0.0"),
            _make_ap("BCLConvert", "1.0.5"),
        ]

        result = resolve_application_profiles([ref], profiles)
        # Should resolve to the highest matching patch
        assert result[("BCLConvert", "~=1.0.0")].version == "1.0.5"

    def test_compatible_release_excludes_higher_minor(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [
            _make_ap("BCLConvert", "1.1.0"),
        ]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")] is None

    def test_compatible_release_excludes_higher_major(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [
            _make_ap("BCLConvert", "2.0.0"),
        ]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")] is None

    def test_compatible_release_selects_highest_patch(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [
            _make_ap("BCLConvert", "1.0.1"),
            _make_ap("BCLConvert", "1.0.99"),
            _make_ap("BCLConvert", "1.0.3"),
        ]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")].version == "1.0.99"

    def test_compatible_release_ignores_non_matching_names(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [
            _make_ap("DragenGermline", "1.0.0"),
            _make_ap("BCLConvert", "1.0.2"),
        ]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")].version == "1.0.2"


class TestExactVersionFallback:
    """Tests for exact version matching when constraint is not a valid specifier."""

    def test_exact_match(self):
        ref = _make_ref("BCLConvert", "1.0.0")
        profiles = [_make_ap("BCLConvert", "1.0.0")]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "1.0.0")] is profiles[0]

    def test_exact_match_no_match(self):
        ref = _make_ref("BCLConvert", "1.0.0")
        profiles = [_make_ap("BCLConvert", "1.0.1")]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "1.0.0")] is None


class TestNoMatch:
    """Tests for cases where no match is found."""

    def test_no_profiles_available(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")

        result = resolve_application_profiles([ref], [])
        assert result[("BCLConvert", "~=1.0.0")] is None

    def test_no_matching_name(self):
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [_make_ap("DragenGermline", "1.0.0")]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")] is None


class TestMultipleReferences:
    """Tests for resolving multiple references at once."""

    def test_multiple_refs_resolved_independently(self):
        refs = [
            _make_ref("BCLConvert", "~=1.0.0"),
            _make_ref("DragenGermline", "~=2.0.0"),
        ]
        profiles = [
            _make_ap("BCLConvert", "1.0.3"),
            _make_ap("DragenGermline", "2.0.1"),
        ]

        result = resolve_application_profiles(refs, profiles)
        assert result[("BCLConvert", "~=1.0.0")].version == "1.0.3"
        assert result[("DragenGermline", "~=2.0.0")].version == "2.0.1"


class TestEdgeCases:
    """Edge case tests."""

    def test_invalid_profile_version_skipped(self):
        """Profiles with unparseable versions are skipped, not errors."""
        ref = _make_ref("BCLConvert", "~=1.0.0")
        profiles = [
            _make_ap("BCLConvert", "not-a-version"),
            _make_ap("BCLConvert", "1.0.2"),
        ]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", "~=1.0.0")].version == "1.0.2"

    def test_empty_references(self):
        result = resolve_application_profiles([], [_make_ap("X", "1.0.0")])
        assert result == {}

    def test_range_specifier(self):
        """Support explicit range specifiers like >=1.0,<1.1."""
        ref = _make_ref("BCLConvert", ">=1.0.0,<1.1.0")
        profiles = [
            _make_ap("BCLConvert", "1.0.5"),
            _make_ap("BCLConvert", "1.1.0"),
        ]

        result = resolve_application_profiles([ref], profiles)
        assert result[("BCLConvert", ">=1.0.0,<1.1.0")].version == "1.0.5"
