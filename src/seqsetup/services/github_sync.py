"""Service for synchronizing profiles and instruments from GitHub."""

import json
import logging
import ssl
import threading
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse

from ..data.instruments import clear_synced_instruments_cache
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
from ..input_rules.profiles import (
    build_application_profile,
    build_test_profile,
    check_application_profile_file,
    check_test_profile_file,
    differing_only_in_capitals,
    repeated_app_versions,
    repeated_test_versions,
    shown_type,
)
from ..input_rules.instruments import (
    check_synced_instrument_file,
    definitions_from,
    duplicate_instruments,
)
from ..input_rules.problems import (
    SYNC_STATUS_BUDGET,
    InputProblem,
    bounded_report,
    problem_line,
)
from .validation import clear_validation_cache
from ..utils.clock import local_time, utcnow


logger = logging.getLogger(__name__)

# The scheduler's sync and an admin's Sync now run in one process and could
# overlap: one sync could clear the "writing" note while the other is still
# writing. So syncs run one at a time.
_SYNC_LOCK = threading.Lock()

_PAUSED_IN_STATUS = ("The settings were only partly written, so Mark Ready is paused "
                     "until a sync writes them again.")
# Starts the message of a sync that finished but could not lift the pause;
# the scheduler then waits its whole interval (services/scheduler.py).
STAYS_PAUSED = "Mark Ready stays paused"

# What the "writing" note names. Synced index kits are not noted: a kit never
# reaches a sheet, because assigning one copies its sequences onto the sample.
_APP_PROFILES = "application profiles"
_TEST_PROFILES = "test profiles"
_INSTRUMENTS = ProfileSyncConfigRepository.INSTRUMENT_SETTINGS
_NOTED_IN_ORDER = (_APP_PROFILES, _TEST_PROFILES, _INSTRUMENTS)


def _names(collections: list[str]) -> str:
    """'a', 'a and b', 'a, b and c', in the order the sync writes them."""
    names = [name for name in _NOTED_IN_ORDER if name in collections]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _refused_kits_text(refused_kits: list[dict]) -> str:
    """Each refused kit file, its kit and why, for the sync's message."""
    return ("Index kit files were refused, so they were not stored: "
            + "; ".join(f"{r['path']} ({r['kit']}): {r['reason']}" if r["kit"]
                        else f"{r['path']}: {r['reason']}" for r in refused_kits)
            + ".")


_SKIPPED_NAMED = 20


def _skipped_list(skipped: list[tuple[str, str]]) -> str:
    """The first files a sync skipped, each with its type, and how many
    more: a long list would be cut where the message is stored, under a
    marker pointing at the list of problems, which they are not in (fresh
    review of f54d3f0, P3 2). Each is logged."""
    named = ", ".join(f"{path} ({shown_type(kind)})" for path, kind in skipped[:_SKIPPED_NAMED])
    more = len(skipped) - _SKIPPED_NAMED
    return named + (f", and {more} more, each named in the log" if more > 0 else "")


def _skipped_text(skipped: list[tuple[str, str]]) -> str:
    """The application profile files a sync left to other tools, for its
    message (docs/design/2026-10-19-lab-profile-layout-design.md)."""
    files = "file" if len(skipped) == 1 else "files"
    return (f"Skipped {len(skipped)} application profile {files} for other tools "
            f"(its type is not Dragen): {_skipped_list(skipped)}.")


def unfinished_sync_message(since: datetime, collections: list[str]) -> str:
    """Why Mark Ready refuses while a sync's writes have not finished (outside
    review of 7f858e0, finding 4; the user's choice, 2026-10-14)."""
    return (f"A configuration sync started at {local_time(since)} did not finish writing the "
            f"{_names(collections)}, so they may be incomplete. Mark Ready is paused until a "
            "sync writes them again. If a sync is running now, try again in a minute; "
            "otherwise an admin can press Sync now on the Config Sync page.")


def paused_page_message(since: datetime, collections: list[str],
                        instruments_synced: bool) -> str:
    """The Config Sync page's line while Mark Ready is paused."""
    then = ("Switch on Also sync instruments, then press Sync now"
            if _INSTRUMENTS in collections and not instruments_synced else "Press Sync now")
    return (f"Mark Ready is paused: a sync started at {local_time(since)} did not finish "
            f"writing the {_names(collections)}. {then} to write them again.")


class SyncResult(tuple):
    """What a sync answers: ``(success, message, count)`` -- every caller
    unpacks it as before -- and ``problems``, every problem the input rules
    found in the files it read, each with its file, line and path
    (docs/design/2026-10-18-input-rules-design.md)."""

    def __new__(cls, success: bool, message: str, count: int, problems=()):
        result = super().__new__(cls, (success, message, count))
        result.problems = list(problems)
        return result


class InstrumentFileRefused(ValueError):
    """An instrument file that does not give valid instruments; the message
    says why (spec 2026-10-04 group A2, §5)."""


class ProfileFileRefused(ValueError):
    """A profile file the input rules refuse; the message is its first
    problem."""


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
        # Every problem the input rules found in this sync's files, errors and
        # warnings, each with its file, line and path
        # (docs/design/2026-10-18-input-rules-design.md).
        self.input_problems: list[InputProblem] = []

    def sync(self) -> SyncResult:
        """
        Perform full sync from GitHub.

        Returns:
            SyncResult: (success, message, count), with ``problems``
        """
        with _SYNC_LOCK:
            success, message, count = self._sync()
            return SyncResult(success, message, count, self.input_problems)

    def _store_status(self, status: str, message: str, count: int, instruments_count: int,
                      index_kits_count: int, repo_url: str, branch: str) -> str:
        """Store the sync's status with its problems, both cut to the status
        budget (one MongoDB document holds them), and return the message as
        stored: a report of thousands of problems would otherwise fill it."""
        report = bounded_report(message, self.input_problems, SYNC_STATUS_BUDGET)
        self.config_repo.update_sync_status(
            status, report["message"], count, instruments_count, index_kits_count,
            repo_url, branch,
            problems=report["problems"], problem_count=report["problem_count"],
            problems_left_out=report["problems_left_out"],
        )
        return report["message"]

    def _sync(self) -> Tuple[bool, str, int]:
        self.input_problems = []
        config = self.config_repo.get()
        # Each collection this sync replaces goes on the "writing" note before
        # it is deleted, and comes off only when the whole sync has finished;
        # while the note names one, Mark Ready is paused (outside review of
        # 7f858e0, finding 4). True from the first note on.
        writing = False
        replaced: list[str] = []

        if not config.github_repo_url:
            return False, "GitHub repository URL not configured", 0

        try:
            # Parse repo URL to owner/repo format
            owner, repo = self._parse_repo_url(config.github_repo_url)
            logger.info(f"Starting sync from {owner}/{repo} branch {config.github_branch}")

            # Fetch application profiles (recursive). Any refused application
            # profile file means no application profile is stored, as for test
            # profiles: a refused newest file made a "~=1.0.0" reference pick
            # the older 1.0.0, and two files of one name and version made a
            # run get either (outside review of f490536, F1 and F10).
            refused_apps: list[str] = []
            app_paths: list[str] = []
            skipped_apps: list[tuple[str, str]] = []
            app_profiles = self._fetch_profiles_recursive(
                owner,
                repo,
                config.github_branch,
                config.application_profiles_path,
                check_application_profile_file,
                build_application_profile,
                strict=True,
                refused=refused_apps,
                paths=app_paths,
                skipped=skipped_apps,
            )
            self._refuse_repeated_app_versions(app_profiles, refused_apps, app_paths)
            logger.info(f"Fetched {len(app_profiles)} application profiles")

            # Fetch test profiles (recursive). Any refused test file means no
            # test profile is stored: a refused newest file would otherwise
            # make a sample's "1" pick an older version (spec 2026-10-07
            # group A4, §1).
            refused_tests: list[str] = []
            test_paths: list[str] = []
            test_profiles = self._fetch_profiles_recursive(
                owner,
                repo,
                config.github_branch,
                config.test_profiles_path,
                check_test_profile_file,
                build_test_profile,
                strict=True,
                refused=refused_tests,
                paths=test_paths,
            )
            self._refuse_repeated_test_versions(test_profiles, refused_tests, test_paths)
            self._refuse_tests_differing_only_in_capitals(test_profiles, refused_tests, test_paths)
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
                refused_instruments += duplicate_instruments(instruments)
                logger.info(f"Fetched {len(instruments)} instrument definitions")

            # Fetch index kits if enabled and repo available. A refused kit
            # file is named in the message and the kit stored before from it
            # stays (the night run's Q3, answered 2026-10-13).
            index_kits = []
            refused_kits: list[dict] = []
            kept_kits: list[IndexKit] = []
            if config.sync_index_kits_enabled and self.index_kit_repo:
                kit_paths: list[str] = []
                index_kits = self._fetch_index_kits(
                    owner,
                    repo,
                    config.github_branch,
                    config.index_kits_path,
                    strict=True,
                    refused=refused_kits,
                    uploaded_ids=frozenset(
                        kit.kit_id for kit in self.index_kit_repo.list_user_uploaded()),
                    paths=kit_paths,
                )
                index_kits = self._refuse_changed_or_repeated_kits(
                    index_kits, kit_paths, refused_kits)
                logger.info(f"Fetched {len(index_kits)} index kits")
                if refused_kits:
                    kept_kits = self._synced_kits_to_keep(index_kits, refused_kits)

            # Guard against accidental data loss on partial/failed fetches.
            # If we already have synced data, never replace it with an empty fetch result.
            existing_app_profiles = self.app_profile_repo.collection.count_documents({})
            existing_test_profiles = self.test_profile_repo.collection.count_documents({})
            if not refused_apps:
                try:
                    self._guard_against_destructive_replace(
                        existing_app_profiles, len(app_profiles), "application profiles"
                    )
                except GitHubSyncError as e:
                    # Every file skipped: say which, not only that none is left
                    # (sol's review of the design).
                    if not skipped_apps:
                        raise
                    raise GitHubSyncError(
                        f"{e}. Every application profile file was skipped, as one for other "
                        f"tools (its type is not Dragen): {_skipped_list(skipped_apps)}."
                    ) from e
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
                try:
                    self._guard_against_destructive_replace(
                        existing_synced_index_kits, len(index_kits) + len(kept_kits),
                        "synced index kits"
                    )
                except GitHubSyncError as e:
                    # Every kit file refused: say which, not only that none is left.
                    if not refused_kits:
                        raise
                    raise GitHubSyncError(f"{e}. {_refused_kits_text(refused_kits)}") from e

            # Save to database (replace all). The deletes and writes below are
            # not one step: each collection is noted before it is deleted.
            if not refused_apps:
                self.config_repo.mark_writing(utcnow(), _APP_PROFILES)
                writing = True
                self.app_profile_repo.delete_all()
                self.app_profile_repo.bulk_save(app_profiles)
                replaced.append(_APP_PROFILES)

            if not refused_tests:
                self.config_repo.mark_writing(utcnow(), _TEST_PROFILES)
                writing = True
                self.test_profile_repo.delete_all()
                self.test_profile_repo.bulk_save(test_profiles)
                replaced.append(_TEST_PROFILES)

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
                switches = self.instrument_definition_repo.enabled_switches()
                disabled_keys = {
                    samplesheet_name
                    for samplesheet_name, enabled in switches
                    if not enabled and samplesheet_name
                }
                # A sync that stopped after deleting the records noted their
                # switches. A noted switch counts only for an instrument that
                # sync did not write again: one it wrote carries the admin's
                # switch, perhaps changed since.
                note = self.config_repo.writing_note()
                if note:
                    stored = {samplesheet_name for samplesheet_name, _enabled in switches}
                    disabled_keys |= set(note["disabled_instruments"]) - stored
                self.config_repo.mark_writing(utcnow(), _INSTRUMENTS, disabled_keys)
                writing = True
                self.instrument_definition_repo.delete_all()
                for inst in instruments:
                    if inst.samplesheet_name in disabled_keys:
                        inst.enabled = False
                self.instrument_definition_repo.bulk_save(instruments)
                replaced.append(_INSTRUMENTS)

            # For index kits, only delete synced ones (preserve user-uploaded)
            if config.sync_index_kits_enabled and self.index_kit_repo:
                self.index_kit_repo.delete_synced_except([kit.kit_id for kit in kept_kits])
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

            # Every write finished, and the caches are cleared: strike off what
            # this sync wrote. What a sync that stopped earlier left incomplete,
            # and this one did not write again, keeps Mark Ready paused.
            still_incomplete = self.config_repo.written(replaced)
            writing = False

            count = ((0 if refused_apps else len(app_profiles))
                     + (0 if refused_tests else len(test_profiles)))
            instruments_count = len(instruments) if store_instruments else 0
            index_kits_count = len(index_kits)

            if (refused_apps or refused_tests or refused_instruments or refused_kits
                    or still_incomplete):
                synced = []
                if not refused_apps:
                    synced.append(f"{len(app_profiles)} application profiles")
                if not refused_tests:
                    synced.append(f"{len(test_profiles)} test profiles")
                if instruments_count > 0:
                    synced.append(f"{instruments_count} instruments")
                if config.sync_index_kits_enabled and self.index_kit_repo:
                    synced.append(f"{index_kits_count} index kits")
                refusals = []
                if refused_apps:
                    refusals.append(
                        "Application profile files were refused, so no application profiles "
                        "were stored and the stored ones are kept: "
                        + "; ".join(refused_apps) + "."
                    )
                    kept = self._kept_app_versions_not_read(app_profiles)
                    if kept:
                        refusals.append(
                            "Kept application profiles this sync did not read: "
                            + ", ".join(kept)
                            + " -- each is in a refused file or no longer in the repository."
                        )
                if refused_tests:
                    refusals.append(
                        "Test profile files were refused, so no test profiles were stored "
                        "and the stored ones are kept: " + "; ".join(refused_tests) + "."
                    )
                    kept = self._kept_test_versions_not_read(test_profiles)
                    if kept:
                        refusals.append(
                            "Kept test profiles this sync did not read: " + ", ".join(kept)
                            + " -- each is in a refused file or no longer in the repository."
                        )
                if refused_instruments:
                    refusals.append(
                        "Instrument files were refused, so no instrument settings were stored "
                        "and the stored ones are kept: " + "; ".join(refused_instruments) + "."
                    )
                if refused_kits:
                    refusals.append(_refused_kits_text(refused_kits))
                    if kept_kits:
                        refusals.append(
                            "Kept the stored index kits "
                            + ", ".join(sorted(f"{kit.name} {kit.version}" for kit in kept_kits))
                            + " until the file is fixed."
                        )
                if still_incomplete:
                    stays = (
                        f"{STAYS_PAUSED}: a sync that stopped earlier left the "
                        f"{_names(still_incomplete)} incomplete, and this sync did not write "
                        "them again."
                    )
                    if _INSTRUMENTS in still_incomplete and not config.sync_instruments_enabled:
                        stays += " Switch on Also sync instruments, then sync again."
                    elif refused_apps or refused_tests or refused_instruments:
                        stays += " Fix the refused files, then sync again."
                    refusals.append(stays)
                message = " ".join(refusals)
                if synced:
                    message += f" Synced {', '.join(synced)}."
                if skipped_apps:
                    message += " " + _skipped_text(skipped_apps)
                message = self._store_status(
                    "error", message, count, instruments_count, index_kits_count,
                    config.github_repo_url, config.github_branch
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

            done = f"Synced {', '.join(parts)}"
            if skipped_apps:
                done += ". " + _skipped_text(skipped_apps)
            message = self._store_status(
                "success", done, count, instruments_count,
                index_kits_count, config.github_repo_url, config.github_branch
            )

            logger.info(f"Sync completed: {message}")
            return True, message, count + instruments_count + index_kits_count

        except GitHubSyncError as e:
            error_msg = str(e)
            if writing:
                error_msg += " " + _PAUSED_IN_STATUS
            error_msg = self._store_status(
                "error", error_msg, 0, 0, 0,
                config.github_repo_url, config.github_branch
            )
            logger.error(f"Sync failed: {error_msg}")
            return False, f"Sync failed: {error_msg}", 0

        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            if writing:
                error_msg += " " + _PAUSED_IN_STATUS
            logger.exception("Sync failed with unexpected error")
            error_msg = self._store_status(
                "error", error_msg, 0, 0, 0,
                config.github_repo_url, config.github_branch
            )
            return False, error_msg, 0

    @staticmethod
    def _parse_repo_url(url: str) -> Tuple[str, str]:
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
        check,
        build,
        strict: bool = False,
        refused: Optional[list[str]] = None,
        paths: Optional[list[str]] = None,
        skipped: Optional[list[tuple[str, str]]] = None,
    ) -> list:
        """Fetch YAML files from directory recursively, check each with the
        input rules and build its profile from the checked value.

        Args:
            owner: GitHub owner
            repo: GitHub repo name
            branch: Branch name
            path: Directory path within repo
            check: the input rules for one file's text (``CheckResult``); its
                problems join ``self.input_problems``
            build: the profile from a checked value and the file's name
            refused: when given, each file or sub-folder that gives no
                profile, for any reason, is added as "<path>: <problem>",
                and a .yaml or .yml ending is read in any case (test
                profiles, spec 2026-10-07 group A4, §1; application
                profiles, outside review of f490536, F1)
            paths: when given, each returned profile's path in the repository
                is appended, in step with the returned list, so a refusal can
                name a file by its path and not by a base name two folders
                can share
            skipped: when given, each file ``check`` leaves alone (an
                application profile for other tools) is added as (path,
                ApplicationType) and gives no profile
                (docs/design/2026-10-19-lab-profile-layout-design.md)

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
                    owner, repo, branch, item_path, check, build, strict=False, refused=refused,
                    paths=paths, skipped=skipped
                )
                profiles.extend(sub_profiles)

            # In the test and application profile folders (``refused`` given)
            # a .YAML or .Yml ending counts too (spec 2026-10-07 group A4, §1,
            # decision 9).
            elif item_type == "file" and (
                item_name.lower() if refused is not None else item_name
            ).endswith((".yaml", ".yml")):
                # Parse YAML file
                download_url = item.get("download_url")
                if download_url:
                    try:
                        content = self._fetch_file_content(download_url)
                        result = check(content, item_path)
                        if result.skipped:
                            if skipped is None:
                                raise ProfileFileRefused(f"{item_path}: is not a file this folder reads")
                            skipped.append((item_path, result.skipped))
                            logger.info(f"Skipped {item_path}: a profile for other tools")
                            continue
                        self.input_problems.extend(result.problems)
                        errors = [p for p in result.problems if p.level == "error"]
                        if errors:
                            for error in errors:
                                logger.warning(f"Profile file {problem_line(error)}")
                            # The first problem only, as for instrument files:
                            # the list of problems has them all.
                            more = (" (and more problems in this file: see the list of problems)"
                                    if len(errors) > 1 else "")
                            raise ProfileFileRefused(problem_line(errors[0]) + more)
                        profile = build(result.value, item_name)
                        profiles.append(profile)
                        if paths is not None:
                            paths.append(item_path)
                        logger.debug(f"Parsed profile from {item_path}")
                    except ProfileFileRefused as e:
                        if refused is not None:
                            refused.append(str(e))
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
                    result = check_synced_instrument_file(content, item_path)
                    self.input_problems.extend(result.problems)
                    errors = [p for p in result.problems if p.level == "error"]
                    if errors:
                        for error in errors:
                            logger.error(f"Instrument file {problem_line(error)}")
                        # The first problem only: all of them once filled the
                        # message, and the cut to fit the store dropped the
                        # refusals after them and STAYS_PAUSED.
                        more = (" (and more problems in this file: see the list of problems)"
                                if len(errors) > 1 else "")
                        raise InstrumentFileRefused(problem_line(errors[0]) + more)
                    for warning in result.problems:
                        logger.warning(f"Instrument file {problem_line(warning)}")
                    parsed = definitions_from(result.value, item_name)
                except InstrumentFileRefused as e:
                    text = str(e) if str(e).startswith(item_path + ":") else f"{item_path}: {e}"
                    refused.append(text)
                    logger.error(f"Refused instrument file {text}")
                except Exception as e:
                    refused.append(f"{item_path}: {e}")
                    logger.error(f"Refused instrument file {item_path}: {e}")
                else:
                    instruments.extend(parsed)
                    logger.debug(f"Parsed {len(parsed)} instruments from {item_path}")

        return instruments, refused

    def _kept_test_versions_not_read(self, test_profiles: list[TestProfile]) -> list[str]:
        """The stored test versions that are not among ``test_profiles``, as
        "<test> <version>". A refused test file keeps every stored profile,
        including a version deleted from the repository on purpose, so the
        refusal says which ones it kept without reading them."""
        read = {(profile.test_type, profile.version) for profile in test_profiles}
        stored = {(profile.test_type, profile.version)
                  for profile in self.test_profile_repo.list_all()}
        return [f"{test} {version}" for test, version in sorted(stored - read)]

    def _kept_app_versions_not_read(self, app_profiles: list[ApplicationProfile]) -> list[str]:
        """As ``_kept_test_versions_not_read``, for application profiles."""
        read = {(profile.name, profile.version) for profile in app_profiles}
        stored = {(profile.name, profile.version)
                  for profile in self.app_profile_repo.list_all()}
        return [f"{name} {version}" for name, version in sorted(stored - read)]

    @staticmethod
    def _refuse_repeated_app_versions(app_profiles: list[ApplicationProfile],
                                      refused: list[str], paths: list[str]) -> None:
        """Each application profile name and version that is in more than one
        file is logged and added to ``refused``: a test's reference would get
        whichever of the files was stored first (outside review of f490536,
        F10). Versions are compared as versions, so "1.0" and "1.0.0" are one:
        a range such as "~=1.0" matches both, while an exact reference finds
        only the one spelled as it is. The profile checks have made sure each
        version is a valid one. ``paths`` are the files' paths in the repository,
        in step with ``app_profiles``, as for ``_refuse_repeated_test_versions``.
        The rule is ``input_rules.profiles.repeated_app_versions``, which the
        settings command uses too."""
        for where in repeated_app_versions(app_profiles, paths):
            logger.warning(
                f"Application profiles refused: {where}. A profile name and version "
                "may be in one file only."
            )
            refused.append(where + "; a profile name and version may be in one file only")

    def _refuse_changed_or_repeated_kits(self, kits: list[IndexKit], paths: list[str],
                                         refused: list[dict]) -> list[IndexKit]:
        """The fetched kits the sync may store. A kit name and version given
        by two files, or stored before with other content (its fingerprint),
        is added to ``refused`` and not stored, so the stored kit stays: while
        a kit is stored its name and version mean the same indexes (a kit whose
        file left the repository is removed, and may come back changed), and a
        drop from a page loaded before cannot pick up new ones (index mix-up
        audit #6, 2026-10-14)."""
        files: dict[str, list[str]] = {}
        # strict=True: a kit without its path would be checked against none.
        for kit, where in zip(kits, paths, strict=True):
            files.setdefault(kit.kit_id, []).append(where)
        stored = {kit.kit_id: kit.fingerprint() for kit in self.index_kit_repo.list_synced()}
        allowed = []
        for kit, where in zip(kits, paths, strict=True):
            others = [path for path in files[kit.kit_id] if path != where]
            if others:
                reason = (f"{', '.join(others)} {'gives' if len(others) == 1 else 'give'} this "
                          f"kit name and version too; a kit name and version may be in one "
                          f"file only")
            elif kit.kit_id in stored and stored[kit.kit_id] != kit.fingerprint():
                reason = ("a kit of this name and version is stored with other indexes or "
                          "settings; give the changed kit a new version")
            else:
                allowed.append(kit)
                continue
            logger.error(f"Index kit '{kit.name}' {kit.version} ({where}): {reason}")
            refused.append({"path": where, "name": kit.name,
                            "kit": f"{kit.name} {kit.version}", "reason": reason})
        return allowed

    def _synced_kits_to_keep(self, fetched: list[IndexKit], refused: list[dict]) -> list[IndexKit]:
        """The stored synced kits a sync with refused kit files keeps: those
        this sync did not read that carry a refused file's kit name, or -- when
        a refused file names no kit -- every one it did not read, since any of
        them could be that file's."""
        fetched_ids = {kit.kit_id for kit in fetched}
        not_read = [kit for kit in self.index_kit_repo.list_synced() if kit.kit_id not in fetched_ids]
        if any(r["name"] is None for r in refused):
            return not_read
        names = {r["name"] for r in refused}
        return [kit for kit in not_read if kit.name in names]

    @staticmethod
    def _refuse_repeated_test_versions(test_profiles: list[TestProfile],
                                       refused: list[str],
                                       paths: Optional[list[str]] = None) -> None:
        """Each test and version that is in more than one file is logged and
        added to ``refused``, since a sample could get any of those files
        (spec 2026-10-07 group A4, §1). ``paths`` are the files' paths in the
        repository, in step with ``test_profiles``: two folders of the tree
        can hold the same base name, and "in Wgs.yaml and Wgs.yaml" says
        nothing about where the second one is."""
        where_of = paths if paths is not None else [p.source_file for p in test_profiles]
        # input_rules.profiles.repeated_test_versions zips with strict=True: a
        # caller that appended a profile without its path fails closed
        # (batch 4 review fix E).
        for where in repeated_test_versions(test_profiles, where_of):
            logger.warning(
                f"Test profiles refused: {where}. A test and version may be in one file only."
            )
            refused.append(where)

    @staticmethod
    def _refuse_tests_differing_only_in_capitals(test_profiles: list[TestProfile],
                                                 refused: list[str],
                                                 paths: Optional[list[str]] = None) -> None:
        """Two tests whose TestType differs only in letter case are logged and
        added to ``refused``. A test is matched by its TestType exactly, so
        ``Wgs`` and ``WGS`` are two tests with their own application profiles,
        while every page and the Sample Sheet show what a reader takes for one
        test (spec 2026-10-07 group A4, what it did not cover). ``paths`` are
        the files' paths in the repository, in step with ``test_profiles``, as
        for ``_refuse_repeated_test_versions`` (the night run's Q7)."""
        where_of = paths if paths is not None else [p.source_file for p in test_profiles]
        for where in differing_only_in_capitals(test_profiles, where_of):
            logger.warning(
                f"Test profiles refused: {where}. Two tests may not differ only in capitals."
            )
            refused.append(where)

    def _fetch_index_kits(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        strict: bool = False,
        refused: Optional[list[dict]] = None,
        uploaded_ids: frozenset = frozenset(),
        paths: Optional[list[str]] = None,
    ) -> list[IndexKit]:
        """Fetch index kit definitions from GitHub.

        Fetches YAML files from the configured path and parses them into IndexKit objects.
        Only valid index kits (passing IndexValidator) are returned. Each file
        that is not is added to ``refused`` as {"path", "name", "kit",
        "reason"}, with name and kit None when the file names no kit (the
        night run's Q3: the sync names it and keeps the kit stored before).
        A kit whose kit_id is in ``uploaded_ids`` -- a kit uploaded through
        SeqSetup -- is refused the same way, and the uploaded one is kept
        (review P2-2, 2026-10-13). ``paths`` gets each returned kit's file
        path, in step with the returned list.

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
            # Its kits are not read, so the sync names it and keeps every
            # stored kit it did not read (review P2-1, 2026-10-13).
            if refused is not None:
                refused.append({"path": path.strip("/"), "name": None, "kit": None,
                                "reason": f"could not be listed: {str(e).rstrip('.')}"})
            return index_kits

        for item in contents:
            item_type = item.get("type")
            item_name = item.get("name", "")
            item_path = item.get("path", "")

            if item_type == "dir":
                # Recurse into subdirectory
                sub_kits = self._fetch_index_kits(owner, repo, branch, item_path,
                                                  refused=refused, uploaded_ids=uploaded_ids,
                                                  paths=paths)
                # Subdirectories are best-effort; top-level fetch is strict.
                index_kits.extend(sub_kits)

            # Any letter case, as for test profiles (review P3-3, 2026-10-13).
            elif item_type == "file" and item_name.lower().endswith((".yaml", ".yml")):
                download_url = item.get("download_url")
                if download_url:
                    try:
                        content = self._fetch_file_content(download_url)
                        kit = IndexKitSyncParser.parse(content, item_name)

                        if kit:
                            # Validate the kit
                            validation = IndexValidator.validate(kit)
                            if validation.is_valid and kit.kit_id in uploaded_ids:
                                logger.error(
                                    f"Index kit '{kit.name}' {kit.version} ({item_path}) has the "
                                    "name and version of a kit uploaded through SeqSetup; "
                                    "the uploaded one is kept"
                                )
                                if refused is not None:
                                    refused.append({
                                        "path": item_path, "name": kit.name,
                                        "kit": f"{kit.name} {kit.version}",
                                        "reason": "a kit of this name and version was uploaded "
                                                  "through SeqSetup, and the uploaded one is kept",
                                    })
                            elif validation.is_valid:
                                index_kits.append(kit)
                                if paths is not None:
                                    paths.append(item_path)
                                logger.debug(f"Parsed index kit from {item_path}")
                            else:
                                for error in validation.errors:
                                    logger.error(
                                        f"Index kit '{kit.name}' ({item_name}): {error}"
                                    )
                                logger.error(
                                    f"Skipping invalid index kit from {item_path}"
                                )
                                if refused is not None:
                                    refused.append({
                                        "path": item_path, "name": kit.name,
                                        "kit": f"{kit.name} {kit.version}",
                                        "reason": "; ".join(e.rstrip(".") for e in validation.errors),
                                    })

                            # Log warnings
                            for warning in validation.warnings:
                                logger.warning(
                                    f"Index kit '{kit.name}' ({item_name}): {warning}"
                                )
                        elif refused is not None:
                            refused.append({"path": item_path, "name": None, "kit": None,
                                            "reason": "could not be read as an index kit"})

                    except Exception as e:
                        logger.warning(f"Failed to process index kit {item_path}: {e}")
                        if refused is not None:
                            refused.append({"path": item_path, "name": None, "kit": None,
                                            "reason": str(e).rstrip(".")})

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
