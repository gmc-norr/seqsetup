"""Service for synchronizing profiles from GitHub."""

import json
import logging
import urllib.request
import urllib.error
from typing import Tuple
from urllib.parse import urlparse

import yaml

from ..models.application_profile import ApplicationProfile
from ..models.test_profile import TestProfile
from ..repositories.application_profile_repo import ApplicationProfileRepository
from ..repositories.test_profile_repo import TestProfileRepository
from ..repositories.profile_sync_config_repo import ProfileSyncConfigRepository


logger = logging.getLogger(__name__)


class GitHubSyncError(Exception):
    """Error during GitHub sync operation."""
    pass


class GitHubSyncService:
    """Service for synchronizing profiles from a public GitHub repository.

    Fetches YAML profile files from GitHub and stores them in MongoDB.
    Supports recursive directory scanning for subdirectories.
    """

    def __init__(
        self,
        config_repo: ProfileSyncConfigRepository,
        app_profile_repo: ApplicationProfileRepository,
        test_profile_repo: TestProfileRepository,
    ):
        self.config_repo = config_repo
        self.app_profile_repo = app_profile_repo
        self.test_profile_repo = test_profile_repo

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

            # Save to database (replace all)
            self.app_profile_repo.delete_all()
            self.app_profile_repo.bulk_save(app_profiles)

            self.test_profile_repo.delete_all()
            self.test_profile_repo.bulk_save(test_profiles)

            count = len(app_profiles) + len(test_profiles)

            # Update sync status
            message = f"Synced {len(app_profiles)} application profiles and {len(test_profiles)} test profiles"
            self.config_repo.update_sync_status("success", message, count)

            logger.info(f"Sync completed: {message}")
            return True, message, count

        except GitHubSyncError as e:
            error_msg = str(e)
            logger.error(f"Sync failed: {error_msg}")
            self.config_repo.update_sync_status("error", error_msg, 0)
            return False, f"Sync failed: {error_msg}", 0

        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logger.exception("Sync failed with unexpected error")
            self.config_repo.update_sync_status("error", error_msg, 0)
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

            with urllib.request.urlopen(request, timeout=30) as response:
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

            with urllib.request.urlopen(request, timeout=30) as response:
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
