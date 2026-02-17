"""Repository for ApplicationProfile database operations."""

from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..models.application_profile import ApplicationProfile
from .base import BaseRepository


class ApplicationProfileRepository(BaseRepository[ApplicationProfile]):
    """Repository for managing ApplicationProfile documents in MongoDB."""

    COLLECTION = "application_profiles"
    MODEL_CLASS = ApplicationProfile

    def get_by_name_version(self, name: str, version_constraint: str) -> Optional[ApplicationProfile]:
        """Get an application profile by name and version constraint.

        This is the primary lookup method for resolving TestProfile references.
        Supports PEP 440 version specifiers (e.g., "~=1.0.0", ">=1.0,<2.0")
        as well as exact version strings (e.g., "1.0.0").
        """
        # Get all profiles with this name
        candidates = self.get_by_name(name)
        if not candidates:
            return None

        # Try parsing as a PEP 440 specifier set (e.g., "~=1.0.0", ">=1.0,<2.0")
        try:
            specifier = SpecifierSet(version_constraint)
        except InvalidSpecifier:
            # Not a valid specifier — try exact version match
            for ap in candidates:
                if ap.version == version_constraint:
                    return ap
            return None

        # Filter candidates whose version satisfies the specifier
        matched: list[tuple[Version, ApplicationProfile]] = []
        for ap in candidates:
            try:
                v = Version(ap.version)
            except InvalidVersion:
                continue
            if v in specifier:
                matched.append((v, ap))

        if not matched:
            return None

        # Return the candidate with the highest version
        matched.sort(key=lambda pair: pair[0], reverse=True)
        return matched[0][1]

    def get_by_name(self, name: str) -> list[ApplicationProfile]:
        """Get all versions of an application profile by name."""
        docs = self.collection.find({"name": name})
        return [ApplicationProfile.from_dict(doc) for doc in docs]

    def delete_all(self) -> int:
        """Delete all application profiles. Used for full resync."""
        result = self.collection.delete_many({})
        return result.deleted_count

    def bulk_save(self, profiles: list[ApplicationProfile]) -> int:
        """Save multiple profiles efficiently."""
        count = 0
        for profile in profiles:
            self.save(profile)
            count += 1
        return count
