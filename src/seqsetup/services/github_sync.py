"""Service for synchronizing profiles and instruments from GitHub."""

import json
import logging
import ssl
import urllib.request
import urllib.error
from typing import Optional, Tuple
from urllib.parse import urlparse

import yaml

from ..models.application_profile import ApplicationProfile
from ..models.index import IndexKit
from ..models.instrument_definition import InstrumentDefinition
from ..models.test_profile import TestProfile
from ..repositories.application_profile_repo import ApplicationProfileRepository
from ..repositories.index_kit_repo import IndexKitRepository
from ..repositories.instrument_definition_repo import InstrumentDefinitionRepository
from ..repositories.test_profile_repo import TestProfileRepository
from ..repositories.profile_sync_config_repo import ProfileSyncConfigRepository
from .index_kit_sync_parser import IndexKitSyncParser
from .index_validator import IndexValidator
from .instrument_validator import validate_instrument_yaml, ValidationResult


logger = logging.getLogger(__name__)


class GitHubSyncError(Exception):
    """Error during GitHub sync operation."""
    pass


class GitHubSyncService:
    """Service for synchronizing profiles and instruments from a public GitHub repository.

    Fetches YAML profile and instrument files from GitHub and stores them in MongoDB.
    Supports recursive directory scanning for subdirectories.
    """

    def __init__(
        self,
        config_repo: ProfileSyncConfigRepository,
        app_profile_repo: ApplicationProfileRepository,
        test_profile_repo: TestProfileRepository,
        instrument_definition_repo: Optional[InstrumentDefinitionRepository] = None,
        index_kit_repo: Optional[IndexKitRepository] = None,
    ):
        self.config_repo = config_repo
        self.app_profile_repo = app_profile_repo
        self.test_profile_repo = test_profile_repo
        self.instrument_definition_repo = instrument_definition_repo
        self.index_kit_repo = index_kit_repo

    def sync(self) -> Tuple[bool, str, int]:
        """
        Perform full sync from GitHub.

        Returns:
            Tuple of (success, message, count)
        """
        config = self.config_repo.get()

        if not config.github_repo_url:
            return False, "GitHub repository URL not configured", 0

        try:
            # Parse repo URL to owner/repo format
            owner, repo = self._parse_repo_url(config.github_repo_url)
            logger.info(f"Starting sync from {owner}/{repo} branch {config.github_branch}")

            # Fetch application profiles (recursive)
            app_profiles = self._fetch_profiles_recursive(
                owner,
                repo,
                config.github_branch,
                config.application_profiles_path,
                self._parse_application_profile,
            )
            logger.info(f"Fetched {len(app_profiles)} application profiles")

            # Fetch test profiles (recursive)
            test_profiles = self._fetch_profiles_recursive(
                owner,
                repo,
                config.github_branch,
                config.test_profiles_path,
                self._parse_test_profile,
            )
            logger.info(f"Fetched {len(test_profiles)} test profiles")

            # Fetch instruments if enabled and repo available
            instruments = []
            if config.sync_instruments_enabled and self.instrument_definition_repo:
                instruments = self._fetch_instruments(
                    owner,
                    repo,
                    config.github_branch,
                    config.instruments_path,
                )
                logger.info(f"Fetched {len(instruments)} instrument definitions")

            # Fetch index kits if enabled and repo available
            index_kits = []
            if config.sync_index_kits_enabled and self.index_kit_repo:
                index_kits = self._fetch_index_kits(
                    owner,
                    repo,
                    config.github_branch,
                    config.index_kits_path,
                )
                logger.info(f"Fetched {len(index_kits)} index kits")

            # Save to database (replace all)
            self.app_profile_repo.delete_all()
            self.app_profile_repo.bulk_save(app_profiles)

            self.test_profile_repo.delete_all()
            self.test_profile_repo.bulk_save(test_profiles)

            if config.sync_instruments_enabled and self.instrument_definition_repo:
                self.instrument_definition_repo.delete_all()
                self.instrument_definition_repo.bulk_save(instruments)

            # For index kits, only delete synced ones (preserve user-uploaded)
            if config.sync_index_kits_enabled and self.index_kit_repo:
                self.index_kit_repo.delete_synced()
                self.index_kit_repo.bulk_save(index_kits)

            count = len(app_profiles) + len(test_profiles)
            instruments_count = len(instruments)
            index_kits_count = len(index_kits)

            # Update sync status
            parts = [
                f"{len(app_profiles)} application profiles",
                f"{len(test_profiles)} test profiles",
            ]
            if instruments_count > 0:
                parts.append(f"{instruments_count} instruments")
            if index_kits_count > 0:
                parts.append(f"{index_kits_count} index kits")

            message = f"Synced {', '.join(parts)}"
            self.config_repo.update_sync_status(
                "success", message, count, instruments_count, index_kits_count
            )

            logger.info(f"Sync completed: {message}")
            return True, message, count + instruments_count + index_kits_count

        except GitHubSyncError as e:
            error_msg = str(e)
            logger.error(f"Sync failed: {error_msg}")
            self.config_repo.update_sync_status("error", error_msg, 0, 0, 0)
            return False, f"Sync failed: {error_msg}", 0

        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logger.exception("Sync failed with unexpected error")
            self.config_repo.update_sync_status("error", error_msg, 0, 0, 0)
            return False, error_msg, 0

    def _parse_repo_url(self, url: str) -> Tuple[str, str]:
        """Parse GitHub URL to extract owner and repo name.

        Handles formats like:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - github.com/owner/repo
        """
        # Normalize URL
        if not url.startswith("http"):
            url = f"https://{url}"

        parsed = urlparse(url)
        path = parsed.path.strip("/")

        # Remove .git suffix if present
        if path.endswith(".git"):
            path = path[:-4]

        parts = path.split("/")
        if len(parts) < 2:
            raise GitHubSyncError(f"Invalid GitHub URL: {url}")

        owner = parts[0]
        repo = parts[1]

        return owner, repo

    def _fetch_directory_contents(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
    ) -> list[dict]:
        """Fetch directory listing from GitHub API."""
        # Clean path
        path = path.strip("/")

        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

        try:
            request = urllib.request.Request(
                api_url,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "SeqSetup-ProfileSync",
                },
            )

            ssl_context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=30, context=ssl_context) as response:
                data = json.loads(response.read().decode("utf-8"))

            # Ensure we have a list
            if isinstance(data, dict):
                # Single file case - GitHub returns object not array
                return [data]
            return data

        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise GitHubSyncError(f"Path not found: {path}")
            raise GitHubSyncError(f"GitHub API error: {e.code} {e.reason}")
        except urllib.error.URLError as e:
            raise GitHubSyncError(f"Network error: {e.reason}")

    def _fetch_file_content(self, download_url: str) -> str:
        """Fetch file content from GitHub."""
        try:
            request = urllib.request.Request(
                download_url,
                headers={"User-Agent": "SeqSetup-ProfileSync"},
            )

            ssl_context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=30, context=ssl_context) as response:
                return response.read().decode("utf-8")

        except urllib.error.HTTPError as e:
            raise GitHubSyncError(f"Failed to fetch file: {e.code} {e.reason}")
        except urllib.error.URLError as e:
            raise GitHubSyncError(f"Network error: {e.reason}")

    def _fetch_profiles_recursive(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        parser,
    ) -> list:
        """Fetch YAML files from directory recursively and parse them.

        Args:
            owner: GitHub owner
            repo: GitHub repo name
            branch: Branch name
            path: Directory path within repo
            parser: Function to parse YAML into model object

        Returns:
            List of parsed profile objects
        """
        profiles = []

        try:
            contents = self._fetch_directory_contents(owner, repo, branch, path)
        except GitHubSyncError as e:
            logger.warning(f"Could not fetch {path}: {e}")
            return profiles

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_profiles = self._fetch_profiles_recursive(
                    owner, repo, branch, item_path, parser
                )
                profiles.extend(sub_profiles)

            elif item_type == "file" and item_name.endswith((".yaml", ".yml")):
                # Parse YAML file
                download_url = item.get("download_url")
                if download_url:
                    try:
                        content = self._fetch_file_content(download_url)
                        yaml_data = yaml.safe_load(content)
                        if yaml_data:
                            profile = parser(yaml_data, item_name)
                            profiles.append(profile)
                            logger.debug(f"Parsed profile from {item_path}")
                    except yaml.YAMLError as e:
                        logger.warning(f"Failed to parse YAML {item_path}: {e}")
                    except Exception as e:
                        logger.warning(f"Failed to process {item_path}: {e}")

        return profiles

    def _fetch_instruments(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
    ) -> list[InstrumentDefinition]:
        """Fetch instrument definitions from GitHub.

        Supports two formats:
        1. Single YAML file with 'instruments' key containing all instruments
           (like the local instruments.yaml)
        2. One YAML file per instrument

        Args:
            owner: GitHub owner
            repo: GitHub repo name
            branch: Branch name
            path: Directory path within repo

        Returns:
            List of InstrumentDefinition objects
        """
        instruments = []

        try:
            contents = self._fetch_directory_contents(owner, repo, branch, path)
        except GitHubSyncError as e:
            logger.warning(f"Could not fetch instruments from {path}: {e}")
            return instruments

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_instruments = self._fetch_instruments(owner, repo, branch, item_path)
                instruments.extend(sub_instruments)

            elif item_type == "file" and item_name.endswith((".yaml", ".yml")):
                download_url = item.get("download_url")
                if download_url:
                    try:
                        content = self._fetch_file_content(download_url)
                        yaml_data = yaml.safe_load(content)
                        if yaml_data:
                            parsed = self._parse_instruments_yaml(yaml_data, item_name)
                            instruments.extend(parsed)
                            logger.debug(f"Parsed {len(parsed)} instruments from {item_path}")
                    except yaml.YAMLError as e:
                        logger.warning(f"Failed to parse instrument YAML {item_path}: {e}")
                    except Exception as e:
                        logger.warning(f"Failed to process instruments {item_path}: {e}")

        return instruments

    def _parse_instruments_yaml(
        self,
        yaml_data: dict,
        filename: str,
    ) -> list[InstrumentDefinition]:
        """Parse YAML data into InstrumentDefinition objects.

        Handles two formats:
        1. Multi-instrument file: {'instruments': {'Name1': {...}, 'Name2': {...}}}
        2. Single-instrument file: {'name': 'Name1', 'samplesheet_name': ...}

        Validates each instrument and logs any errors or warnings.
        Invalid instruments (with errors) are skipped.
        """
        instruments = []

        # Check if this is a multi-instrument file (like instruments.yaml)
        if "instruments" in yaml_data and isinstance(yaml_data["instruments"], dict):
            for name, config in yaml_data["instruments"].items():
                config["name"] = name  # Add name from key
                validation = self._validate_and_parse_instrument(config, filename)
                if validation:
                    instruments.append(validation)
        # Check if this is a single-instrument file
        elif "samplesheet_name" in yaml_data or "chemistry_type" in yaml_data or "name" in yaml_data:
            validation = self._validate_and_parse_instrument(yaml_data, filename)
            if validation:
                instruments.append(validation)

        return instruments

    def _validate_and_parse_instrument(
        self,
        yaml_data: dict,
        filename: str,
    ) -> Optional[InstrumentDefinition]:
        """Validate and parse a single instrument definition.

        Args:
            yaml_data: Instrument configuration dict
            filename: Source filename for error reporting

        Returns:
            InstrumentDefinition if valid, None if validation failed with errors
        """
        # Validate the instrument data
        result = validate_instrument_yaml(yaml_data, filename)
        instrument_name = yaml_data.get("name", filename)

        # Log any warnings
        for warning in result.warnings:
            logger.warning(f"Instrument '{instrument_name}' ({filename}): {warning}")

        # Log errors and skip invalid instruments
        if not result.is_valid:
            for error in result.errors:
                logger.error(f"Instrument '{instrument_name}' ({filename}): {error}")
            logger.error(f"Skipping invalid instrument '{instrument_name}' from {filename}")
            return None

        # Parse the valid instrument
        instrument = InstrumentDefinition.from_yaml(yaml_data, filename)

        # If name not in file, derive from filename
        if not instrument.name:
            instrument.name = filename.replace(".yaml", "").replace(".yml", "").replace("-", " ").replace("_", " ").title()

        return instrument

    def _parse_application_profile(
        self,
        yaml_data: dict,
        filename: str,
    ) -> ApplicationProfile:
        """Parse YAML into ApplicationProfile."""
        return ApplicationProfile.from_yaml(yaml_data, filename)

    def _parse_test_profile(
        self,
        yaml_data: dict,
        filename: str,
    ) -> TestProfile:
        """Parse YAML into TestProfile."""
        return TestProfile.from_yaml(yaml_data, filename)

    def _fetch_index_kits(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
    ) -> list[IndexKit]:
        """Fetch index kit definitions from GitHub.

        Fetches YAML files from the configured path and parses them into IndexKit objects.
        Only valid index kits (passing IndexValidator) are returned.

        Args:
            owner: GitHub owner
            repo: GitHub repo name
            branch: Branch name
            path: Directory path within repo

        Returns:
            List of IndexKit objects
        """
        index_kits = []

        try:
            contents = self._fetch_directory_contents(owner, repo, branch, path)
        except GitHubSyncError as e:
            logger.warning(f"Could not fetch index kits from {path}: {e}")
            return index_kits

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_kits = self._fetch_index_kits(owner, repo, branch, item_path)
                index_kits.extend(sub_kits)

            elif item_type == "file" and item_name.endswith((".yaml", ".yml")):
                download_url = item.get("download_url")
                if download_url:
                    try:
                        content = self._fetch_file_content(download_url)
                        kit = IndexKitSyncParser.parse(content, item_name)

                        if kit:
                            # Validate the kit
                            validation = IndexValidator.validate(kit)
                            if validation.is_valid:
                                index_kits.append(kit)
                                logger.debug(f"Parsed index kit from {item_path}")
                            else:
                                for error in validation.errors:
                                    logger.error(
                                        f"Index kit '{kit.name}' ({item_name}): {error}"
                                    )
                                logger.error(
                                    f"Skipping invalid index kit from {item_path}"
                                )

                            # Log warnings
                            for warning in validation.warnings:
                                logger.warning(
                                    f"Index kit '{kit.name}' ({item_name}): {warning}"
                                )

                    except Exception as e:
                        logger.warning(f"Failed to process index kit {item_path}: {e}")

        return index_kits
