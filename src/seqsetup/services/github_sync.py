"""Service for synchronizing profiles and instruments from GitHub."""

import json
import logging
import ssl
import urllib.request
import urllib.error
from typing import Optional, Tuple
from urllib.parse import urlparse

import yaml

from ..utils.yaml_safety import safe_load_strict
from ..data.instruments import clear_synced_instruments_cache
from ..models.application_profile import ApplicationProfile
from ..models.index import IndexKit
from ..models.instrument_definition import InstrumentDefinition, InstrumentRecordError
from ..models.test_profile import TestProfile
from ..repositories.application_profile_repo import ApplicationProfileRepository
from ..repositories.index_kit_repo import IndexKitRepository
from ..repositories.instrument_definition_repo import InstrumentDefinitionRepository
from ..repositories.test_profile_repo import TestProfileRepository
from ..repositories.profile_sync_config_repo import ProfileSyncConfigRepository
from .index_kit_sync_parser import IndexKitSyncParser
from .index_validator import IndexValidator
from .instrument_validator import validate_instrument_yaml, ValidationResult
from .validation import clear_validation_cache


logger = logging.getLogger(__name__)


class InstrumentFileRefused(ValueError):
    """An instrument file that does not give valid instruments; the message
    says why (spec 2026-10-04 group A2, §5)."""


class GitHubSyncError(Exception):
    """Error during GitHub sync operation."""
    pass


# Hostnames the file-fetch path is allowed to talk to. Strict exact-match
# allowlist: ``raw.githubusercontent.com`` for repo file content,
# ``api.github.com`` for directory listings. We deliberately do NOT allow a
# ``*.githubusercontent.com`` suffix-match: that would tolerate
# ``evil.githubusercontent.com`` if GitHub ever introduces user-controlled
# subdomain space (Pages did, historically). Redirects are forbidden by
# ``_GITHUB_OPENER`` below, so we don't need a wildcard to follow them.
_GITHUB_CONTENT_HOSTS = ("raw.githubusercontent.com",)
_GITHUB_API_HOST = "api.github.com"

# Per-fetch response size cap. YAML config files are kilobytes in practice;
# a multi-MB body suggests a malicious payload (anchor amplification before
# parse, or a redirected target). 10 MB matches the LIMS-API cap shape.
_MAX_GITHUB_RESPONSE_SIZE = 10 * 1024 * 1024


class _NoRedirectHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler that refuses 3xx redirects.

    Following redirects would re-resolve the URL through ``urllib`` and
    bypass ``_validate_github_content_host`` on subsequent hops. We validate
    only the initial URL; refusing redirects keeps that single validation
    load-bearing.
    """


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Raise on any 3xx response instead of following it."""

    def http_error_301(self, req, fp, code, msg, headers):  # noqa: D401
        raise GitHubSyncError(
            f"Refusing to follow {code} redirect from {req.full_url!r}: "
            "GitHub-content fetches must not redirect off-host."
        )

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _build_github_opener() -> urllib.request.OpenerDirector:
    """Build a urllib opener with HTTPS only and no redirect handling.

    Strips the default opener's ``HTTPHandler``, ``FileHandler``,
    ``FTPHandler`` and ``HTTPRedirectHandler`` so a malicious URL or
    redirect chain cannot escape the HTTPS+allowlist envelope.
    """
    opener = urllib.request.OpenerDirector()
    opener.add_handler(_NoRedirectHTTPSHandler())
    opener.add_handler(_NoRedirectHandler())
    # Without these, process_response never dispatches non-2xx responses: the
    # no-redirect handler above would never fire (a 3xx would be returned, not
    # refused) and 4xx/5xx would not raise HTTPError. HTTPErrorProcessor routes
    # non-2xx into the error handlers; HTTPDefaultErrorHandler raises HTTPError
    # for anything not otherwise handled.
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    return opener


_GITHUB_OPENER = _build_github_opener()


def _validate_github_content_host(url: str) -> None:
    """Raise GitHubSyncError if ``url`` points outside the GitHub content hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise GitHubSyncError(
            f"Refused to fetch GitHub content over non-HTTPS scheme: {parsed.scheme!r}"
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise GitHubSyncError(f"Refused to fetch GitHub content with empty host: {url!r}")
    if host in _GITHUB_CONTENT_HOSTS:
        return
    raise GitHubSyncError(
        f"Refused to fetch from non-GitHub host {host!r}. "
        f"Expected one of: {', '.join(_GITHUB_CONTENT_HOSTS)}"
    )


def _validate_github_api_host(url: str) -> None:
    """Raise GitHubSyncError if ``url`` doesn't target ``api.github.com``."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise GitHubSyncError(
            f"Refused to call GitHub API over non-HTTPS scheme: {parsed.scheme!r}"
        )
    host = (parsed.hostname or "").lower()
    if host != _GITHUB_API_HOST:
        raise GitHubSyncError(
            f"Refused to call non-GitHub API host {host!r}. Expected: {_GITHUB_API_HOST}"
        )


def _read_bounded(response, label: str) -> bytes:
    """Read at most ``_MAX_GITHUB_RESPONSE_SIZE`` bytes from ``response``.

    The ``read(N + 1)`` pattern lets us detect over-cap without first
    buffering an unbounded body. Used by the directory-listing and file-
    fetch helpers so a malicious or compromised endpoint cannot OOM the
    process with an arbitrarily large response.
    """
    data = response.read(_MAX_GITHUB_RESPONSE_SIZE + 1)
    if len(data) > _MAX_GITHUB_RESPONSE_SIZE:
        raise GitHubSyncError(
            f"GitHub {label} response exceeds {_MAX_GITHUB_RESPONSE_SIZE} bytes"
        )
    return data


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
                strict=True,
            )
            logger.info(f"Fetched {len(app_profiles)} application profiles")

            # Fetch test profiles (recursive). Any refused test file means no
            # test profile is stored: a refused newest file would otherwise
            # make a sample's "1" pick an older version (spec 2026-10-07
            # group A4, §1).
            refused_tests: list[str] = []
            test_profiles = self._fetch_profiles_recursive(
                owner,
                repo,
                config.github_branch,
                config.test_profiles_path,
                self._parse_test_profile,
                strict=True,
                refused=refused_tests,
            )
            self._refuse_repeated_test_versions(test_profiles, refused_tests)
            logger.info(f"Fetched {len(test_profiles)} test profiles")

            # Fetch instruments if enabled and repo available. Any refused
            # instrument file means no instrument records are stored (spec
            # 2026-10-04 group A2, §5).
            instruments = []
            refused_instruments: list[str] = []
            if config.sync_instruments_enabled and self.instrument_definition_repo:
                instruments, refused_instruments = self._fetch_instruments(
                    owner,
                    repo,
                    config.github_branch,
                    config.instruments_path,
                    strict=True,
                )
                refused_instruments += self._duplicate_instruments(instruments)
                logger.info(f"Fetched {len(instruments)} instrument definitions")

            # Fetch index kits if enabled and repo available
            index_kits = []
            if config.sync_index_kits_enabled and self.index_kit_repo:
                index_kits = self._fetch_index_kits(
                    owner,
                    repo,
                    config.github_branch,
                    config.index_kits_path,
                    strict=True,
                )
                logger.info(f"Fetched {len(index_kits)} index kits")

            # Guard against accidental data loss on partial/failed fetches.
            # If we already have synced data, never replace it with an empty fetch result.
            existing_app_profiles = self.app_profile_repo.collection.count_documents({})
            existing_test_profiles = self.test_profile_repo.collection.count_documents({})
            self._guard_against_destructive_replace(
                existing_app_profiles, len(app_profiles), "application profiles"
            )
            if not refused_tests:
                self._guard_against_destructive_replace(
                    existing_test_profiles, len(test_profiles), "test profiles"
                )

            store_instruments = (
                config.sync_instruments_enabled
                and self.instrument_definition_repo is not None
                and not refused_instruments
            )
            if store_instruments:
                existing_instruments = (
                    self.instrument_definition_repo.collection.count_documents({})
                )
                self._guard_against_destructive_replace(
                    existing_instruments, len(instruments), "instrument definitions"
                )

            if config.sync_index_kits_enabled and self.index_kit_repo:
                existing_synced_index_kits = self.index_kit_repo.collection.count_documents(
                    {"source": "github"}
                )
                self._guard_against_destructive_replace(
                    existing_synced_index_kits, len(index_kits), "synced index kits"
                )

            # Save to database (replace all)
            self.app_profile_repo.delete_all()
            self.app_profile_repo.bulk_save(app_profiles)

            if not refused_tests:
                self.test_profile_repo.delete_all()
                self.test_profile_repo.bulk_save(test_profiles)

            if store_instruments:
                # Preserve the operator-set ``enabled`` flag across the
                # delete+replace. Without this, an admin who disables (say)
                # the HiSeq instrument loses that setting on every scheduled
                # sync because ``bulk_save`` writes fresh records that default
                # to ``enabled=True`` and with regenerated UUIDs. Match by
                # ``samplesheet_name`` (stable across syncs, unique per
                # instrument) rather than ``id`` (regenerated). Only the two
                # fields are read, so a stored record that cannot be loaded
                # does not stop the sync that replaces it.
                disabled_keys = {
                    samplesheet_name
                    for samplesheet_name, enabled
                    in self.instrument_definition_repo.enabled_switches()
                    if not enabled and samplesheet_name
                }
                self.instrument_definition_repo.delete_all()
                for inst in instruments:
                    if inst.samplesheet_name in disabled_keys:
                        inst.enabled = False
                self.instrument_definition_repo.bulk_save(instruments)

            # For index kits, only delete synced ones (preserve user-uploaded)
            if config.sync_index_kits_enabled and self.index_kit_repo:
                self.index_kit_repo.delete_synced()
                self.index_kit_repo.bulk_save(index_kits)

            # Drop the in-memory instrument definitions so every caller of
            # sync() — the admin route and the background scheduler — sees
            # the new ones (i5 orientation, flowcell lanes, kit cycles).
            # Before the validation cache below, so a validation that runs in
            # between cannot be memoized against the old instruments.
            clear_synced_instruments_cache()

            # Invalidate cached validation results. ValidationService memoizes
            # by (run.id, run.updated_at, repo identity), but a bulk_save into
            # an existing repo changes content without changing repo identity
            # or any run's updated_at — so a stale cache entry could mark a
            # run Ready against the *previous* profile set. Clear the cache so
            # the next validate_run() re-computes against the new content.
            clear_validation_cache()

            count = len(app_profiles) + (0 if refused_tests else len(test_profiles))
            instruments_count = len(instruments) if store_instruments else 0
            index_kits_count = len(index_kits)

            if refused_tests or refused_instruments:
                synced = [f"{len(app_profiles)} application profiles"]
                if not refused_tests:
                    synced.append(f"{len(test_profiles)} test profiles")
                if instruments_count > 0:
                    synced.append(f"{instruments_count} instruments")
                if config.sync_index_kits_enabled and self.index_kit_repo:
                    synced.append(f"{index_kits_count} index kits")
                refusals = []
                if refused_tests:
                    refusals.append(
                        "Test profile files were refused, so no test profiles were stored "
                        "and the stored ones are kept: " + "; ".join(refused_tests) + "."
                    )
                if refused_instruments:
                    refusals.append(
                        "Instrument files were refused, so no instrument settings were stored "
                        "and the stored ones are kept: " + "; ".join(refused_instruments) + "."
                    )
                message = " ".join(refusals) + f" Synced {', '.join(synced)}."
                self.config_repo.update_sync_status(
                    "error", message, count, instruments_count, index_kits_count
                )
                logger.error(f"Sync refused files: {message}")
                return False, message, count + instruments_count + index_kits_count

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
        _validate_github_api_host(api_url)

        try:
            request = urllib.request.Request(
                api_url,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "SeqSetup-ProfileSync",
                },
            )

            # ``_GITHUB_OPENER`` is HTTPS-only and refuses 3xx redirects so a
            # malicious or compromised endpoint cannot steer the request off
            # the validated host. Size-capped read protects against OOM from
            # a huge response (anchor-amplification YAML before parse, etc).
            with _GITHUB_OPENER.open(request, timeout=30) as response:
                data = json.loads(_read_bounded(response, "API").decode("utf-8"))

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
        """Fetch file content from GitHub.

        The download_url comes from the GitHub API's directory listing and
        normally points at ``*.githubusercontent.com``. Validate the host
        explicitly so a compromised or maliciously-configured GitHub
        Enterprise endpoint can't redirect us to fetch from an arbitrary host.
        """
        _validate_github_content_host(download_url)
        try:
            request = urllib.request.Request(
                download_url,
                headers={"User-Agent": "SeqSetup-ProfileSync"},
            )

            # See ``_fetch_directory_contents`` for the opener + size-cap
            # rationale. Same envelope: no redirects, no non-HTTPS handlers,
            # bounded read.
            with _GITHUB_OPENER.open(request, timeout=30) as response:
                return _read_bounded(response, "file").decode("utf-8")

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
        strict: bool = False,
        refused: Optional[list[str]] = None,
    ) -> list:
        """Fetch YAML files from directory recursively and parse them.

        Args:
            owner: GitHub owner
            repo: GitHub repo name
            branch: Branch name
            path: Directory path within repo
            parser: Function to parse YAML into model object
            refused: when given, each file or sub-folder that gives no
                profile, for any reason, is added as "<path>: <problem>",
                and a .yaml or .yml ending is read in any case (test
                profiles, spec 2026-10-07 group A4, §1)

        Returns:
            List of parsed profile objects
        """
        profiles = []

        try:
            contents = self._fetch_directory_contents(owner, repo, branch, path)
        except GitHubSyncError as e:
            if strict:
                raise
            logger.warning(f"Could not fetch {path}: {e}")
            if refused is not None:
                refused.append(f"{path.strip('/')}/: could not be listed: {e}")
            return profiles

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_profiles = self._fetch_profiles_recursive(
                    owner, repo, branch, item_path, parser, strict=False, refused=refused
                )
                profiles.extend(sub_profiles)

            # In the test profile folder (``refused`` given) a .YAML or .Yml
            # ending counts too (spec 2026-10-07 group A4, §1, decision 9).
            elif item_type == "file" and (
                item_name.lower() if refused is not None else item_name
            ).endswith((".yaml", ".yml")):
                # Parse YAML file
                download_url = item.get("download_url")
                if download_url:
                    try:
                        content = self._fetch_file_content(download_url)
                        yaml_data = safe_load_strict(content)
                        if yaml_data:
                            profile = parser(yaml_data, item_name)
                            profiles.append(profile)
                            logger.debug(f"Parsed profile from {item_path}")
                        elif refused is not None:
                            refused.append(f"{item_path}: is empty")
                    except yaml.YAMLError as e:
                        logger.warning(f"Failed to parse YAML {item_path}: {e}")
                        if refused is not None:
                            refused.append(f"{item_path}: cannot be read as YAML: {e}")
                    except Exception as e:
                        logger.warning(f"Failed to process {item_path}: {e}")
                        if refused is not None:
                            refused.append(f"{item_path}: {e}")
                elif refused is not None:
                    refused.append(f"{item_path}: has no download link")

        return profiles

    def _fetch_instruments(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        strict: bool = False,
    ) -> Tuple[list[InstrumentDefinition], list[str]]:
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
            (instruments, refused): the InstrumentDefinition objects, and for
            each instrument file or folder that did not give valid
            instruments, for any reason, "<path>: <problem>" (spec
            2026-10-04 group A2, §5). A top-level folder that cannot be
            listed raises when ``strict``.
        """
        instruments = []
        refused = []

        try:
            contents = self._fetch_directory_contents(owner, repo, branch, path)
        except GitHubSyncError as e:
            if strict:
                raise
            return instruments, [f"{path.strip('/')}/: could not be listed: {e}"]

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_instruments, sub_refused = self._fetch_instruments(
                    owner, repo, branch, item_path
                )
                instruments.extend(sub_instruments)
                refused.extend(sub_refused)

            elif item_type == "file" and item_name.endswith((".yaml", ".yml")):
                download_url = item.get("download_url")
                try:
                    if not download_url:
                        raise InstrumentFileRefused("has no download link")
                    content = self._fetch_file_content(download_url)
                    try:
                        yaml_data = safe_load_strict(content)
                    except yaml.YAMLError as e:
                        raise InstrumentFileRefused(f"cannot be read as YAML: {e}") from e
                    parsed = self._parse_instruments_yaml(yaml_data, item_name)
                except Exception as e:
                    refused.append(f"{item_path}: {e}")
                    logger.error(f"Refused instrument file {item_path}: {e}")
                else:
                    instruments.extend(parsed)
                    logger.debug(f"Parsed {len(parsed)} instruments from {item_path}")

        return instruments, refused

    @staticmethod
    def _duplicate_instruments(instruments: list[InstrumentDefinition]) -> list[str]:
        """Two instrument files may not give the same name or samplesheet
        name (spec 2026-10-04 group A2, §1)."""
        problems = []
        for field_name in ("name", "samplesheet_name"):
            seen: dict[str, str] = {}
            for inst in instruments:
                value = getattr(inst, field_name)
                if value in seen:
                    problems.append(
                        f"{seen[value]} and {inst.source_file} both give {field_name} {value!r}"
                    )
                else:
                    seen[value] = inst.source_file
        return problems

    def _parse_instruments_yaml(
        self,
        yaml_data,
        filename: str,
    ) -> list[InstrumentDefinition]:
        """Parse YAML data into InstrumentDefinition objects.

        Handles two formats:
        1. Multi-instrument file: {'instruments': {'Name1': {...}, 'Name2': {...}}}
        2. Single-instrument file: {'name': 'Name1', 'samplesheet_name': ...}

        Raises InstrumentFileRefused, listing every problem, when any
        instrument in the file is not valid or the file describes none: the
        file is refused as a whole (spec 2026-10-04 group A2, §5).
        """
        if isinstance(yaml_data, dict) and isinstance(yaml_data.get("instruments"), dict):
            # A multi-instrument file (like instruments.yaml)
            entries = [
                {**config, "name": name} if isinstance(config, dict) else config
                for name, config in yaml_data["instruments"].items()
            ]
        elif isinstance(yaml_data, dict) and (
            "samplesheet_name" in yaml_data or "chemistry_type" in yaml_data or "name" in yaml_data
        ):
            entries = [yaml_data]
        else:
            entries = []
        if not entries:
            raise InstrumentFileRefused("does not describe an instrument")

        instruments, problems = [], []
        for entry in entries:
            if not isinstance(entry, dict):
                problems.append("an instrument entry must be a mapping")
                continue
            try:
                instruments.append(self._validate_and_parse_instrument(entry, filename))
            except InstrumentFileRefused as e:
                problems.append(str(e))
        if problems:
            raise InstrumentFileRefused("; ".join(problems))
        return instruments

    def _validate_and_parse_instrument(
        self,
        yaml_data: dict,
        filename: str,
    ) -> InstrumentDefinition:
        """Validate and parse a single instrument definition.

        Args:
            yaml_data: Instrument configuration dict
            filename: Source filename for error reporting

        Returns:
            The InstrumentDefinition.

        Raises:
            InstrumentFileRefused: naming the instrument and every problem the
                validator or the model found.
        """
        # Validate the instrument data
        result = validate_instrument_yaml(yaml_data, filename)
        instrument_name = yaml_data.get("name", filename)

        # Log any warnings
        for warning in result.warnings:
            logger.warning(f"Instrument '{instrument_name}' ({filename}): {warning}")

        if not result.is_valid:
            raise InstrumentFileRefused(
                f"{instrument_name}: " + "; ".join(str(error) for error in result.errors)
            )

        # Parse the valid instrument
        try:
            instrument = InstrumentDefinition.from_yaml(yaml_data, filename)
        except InstrumentRecordError as e:
            raise InstrumentFileRefused(str(e)) from e

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

    @staticmethod
    def _refuse_repeated_test_versions(test_profiles: list[TestProfile],
                                       refused: list[str]) -> None:
        """Each test and version that is in more than one file is logged and
        added to ``refused``, since a sample could get any of those files
        (spec 2026-10-07 group A4, §1)."""
        files: dict[tuple[str, str], list[str]] = {}
        for profile in test_profiles:
            files.setdefault((profile.test_type, profile.version), []).append(profile.source_file)
        for (test, version), names in files.items():
            if len(names) > 1:
                names = sorted(names)
                where = f"{test} {version} is in {', '.join(names[:-1])} and {names[-1]}"
                logger.warning(
                    f"Test profiles refused: {where}. A test and version may be in one file only."
                )
                refused.append(where)

    def _fetch_index_kits(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        strict: bool = False,
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
            if strict:
                raise
            logger.warning(f"Could not fetch index kits from {path}: {e}")
            return index_kits

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_kits = self._fetch_index_kits(owner, repo, branch, item_path)
                # Subdirectories are best-effort; top-level fetch is strict.
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

    @staticmethod
    def _guard_against_destructive_replace(
        existing_count: int, fetched_count: int, data_type: str
    ) -> None:
        """Fail-safe guard: never replace non-empty synced data with an empty fetch."""
        if existing_count > 0 and fetched_count == 0:
            raise GitHubSyncError(
                f"Refusing to replace {existing_count} existing {data_type} with 0 fetched items"
            )
