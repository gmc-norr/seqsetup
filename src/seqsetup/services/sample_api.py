"""Service for fetching worksheets and samples from an external API."""

import http.client
import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import time
from urllib.parse import urlparse
from typing import Optional, Tuple

from ..models.sample_api_config import SampleApiConfig
from ..models.sequencing_run import MAX_SAMPLES_PER_RUN

logger = logging.getLogger(__name__)

# Maximum API response size (10 MB)
_MAX_RESPONSE_SIZE = 10 * 1024 * 1024

# Per-field character cap on values extracted from LIMS payloads. Matches the
# 256-char limit applied by form-submission paths so model invariants never
# see an unbounded string regardless of which ingest route was taken.
_MAX_FIELD_LEN = 256


# Minimum interval between consecutive LIMS API calls (per host). Defends
# against runaway admin operations or buggy UI re-firing requests from
# flooding the LIMS. Default 100ms = 10 req/sec ceiling; override with
# SEQSETUP_LIMS_MIN_INTERVAL_MS=<int>.
def _min_interval_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("SEQSETUP_LIMS_MIN_INTERVAL_MS", "100"))) / 1000.0
    except ValueError:
        return 0.1


_LAST_REQUEST_AT: dict[str, float] = {}
_RATE_LIMIT_LOCK = threading.Lock()


def _throttle(host: str) -> None:
    """Sleep just long enough to keep at most one request per host per interval.

    Per-host so multiple LIMS endpoints don't share a budget. Synchronous —
    admin operations aren't latency-critical; the alternative (queue) is
    over-design for this audit finding.
    """
    interval = _min_interval_seconds()
    if interval <= 0:
        return
    with _RATE_LIMIT_LOCK:
        last = _LAST_REQUEST_AT.get(host, 0.0)
        now = time.monotonic()
        wait = (last + interval) - now
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        _LAST_REQUEST_AT[host] = now


class SampleApiError(Exception):
    """Error during sample API fetch."""
    pass


class LimsUrlValidationError(SampleApiError):
    """The configured LIMS URL was refused by ``_validate_url``.

    Subclass of ``SampleApiError`` so existing broad exception handling
    keeps working; callers that need to distinguish a policy refusal (for
    auditing) from a generic network failure catch this type specifically.
    """
    pass


# Extra IPv4 ranges that ``ipaddress.is_private`` does NOT cover but should
# never be reachable from a clinical app: CGNAT (RFC 6598) and IETF protocol
# assignments (RFC 6890). Cloud-host neighbors can sit on CGNAT; protocol-
# assignment space leaks across cloud tenancy boundaries in known cases.
_EXTRA_BLOCKED_V4 = (
    ipaddress.ip_network("100.64.0.0/10"),    # RFC 6598 CGNAT
    ipaddress.ip_network("192.0.0.0/24"),     # RFC 6890 protocol assignments
)


def _is_private_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``ip`` is loopback, link-local, private, multicast, reserved,
    unspecified, or in one of the extra-blocked ranges (CGNAT, IETF protocol
    assignments) — i.e. anything that points at the host's own networks or
    at infrastructure that should never carry LIMS traffic.

    Used by ``_validate_url`` to refuse SSRF targets: even with admin auth,
    the LIMS URL must not be able to address the host's loopback
    (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10), RFC1918
    private, or CGNAT ranges.
    """
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _EXTRA_BLOCKED_V4)
    return False


def _resolve_hostname_ips(
    hostname: str,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve ``hostname`` to all of its A/AAAA records (deduplicated).

    Raises ``SampleApiError`` if resolution fails — we cannot validate a
    target we cannot resolve, and proceeding would leak the API key to an
    unknown destination.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise LimsUrlValidationError(f"Cannot resolve LIMS hostname {hostname!r}: {exc}")
    seen: set[str] = set()
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        ip_text = sockaddr[0]
        if ip_text in seen:
            continue
        seen.add(ip_text)
        try:
            ips.append(ipaddress.ip_address(ip_text))
        except ValueError:
            # getaddrinfo handed back something we can't parse — refuse.
            raise LimsUrlValidationError(f"Unparseable resolved address for {hostname!r}: {ip_text!r}")
    return ips


def _validate_url(
    url: str,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Validate the URL and return the resolved+validated IPs.

    Returns the IPs the caller MUST pin its connection to. This single
    resolve-and-validate pass is the trust boundary: any subsequent code
    that re-resolves the hostname re-opens a DNS rebinding window.

    Two independent restrictions:

    1. Scheme: ``https`` always allowed; ``http`` only if the operator opts
       in via ``SEQSETUP_LIMS_ALLOW_HTTP=1`` — plain HTTP would leak the
       configured api-key on the wire.

    2. Address: the hostname must resolve to public addresses only.
       Loopback, link-local, RFC1918 private, multicast, reserved,
       unspecified, CGNAT, and IETF protocol-assignment ranges are refused
       after DNS resolution. Operators whose LIMS lives on a private
       corporate network opt in via ``SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1``
       — a deliberate per-deployment decision that disables only the
       private-range check, not the pinning that follows.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise LimsUrlValidationError("URL has no hostname")
    if parsed.scheme not in ("http", "https"):
        raise LimsUrlValidationError(f"Unsupported URL scheme: {parsed.scheme}")

    if parsed.scheme == "http":
        opt_in_http = os.environ.get("SEQSETUP_LIMS_ALLOW_HTTP", "").lower() in ("1", "true", "yes")
        if not opt_in_http:
            raise LimsUrlValidationError(
                f"Refusing to call LIMS over plain HTTP at {hostname!r}: "
                f"the configured api-key would be sent in clear text. "
                f"Use HTTPS, or set SEQSETUP_LIMS_ALLOW_HTTP=1 to opt in (not for production)."
            )

    resolved = _resolve_hostname_ips(hostname)
    if not resolved:
        raise LimsUrlValidationError(f"Hostname {hostname!r} resolved to no addresses")

    allow_private = os.environ.get("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", "").lower() in ("1", "true", "yes")
    if not allow_private:
        for ip in resolved:
            if _is_private_address(ip):
                raise LimsUrlValidationError(
                    f"Refusing to call LIMS at {hostname!r} ({ip}): address is "
                    f"loopback/private/link-local/CGNAT. SSRF is blocked by policy. "
                    f"For dev/test against a mock LIMS or a corporate-network LIMS, "
                    f"set SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1."
                )

    return resolved


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """``HTTPSConnection`` that connects to a pre-validated IP, not whatever
    the OS DNS resolves at connect time. Closes the DNS rebinding TOCTOU
    where validation and ``urlopen`` would each resolve the hostname
    independently. The hostname is kept for the ``Host:`` header and TLS
    SNI / certificate validation.
    """

    def __init__(self, *args, pinned_ip: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain-HTTP analogue of ``_PinnedHTTPSConnection``."""

    def __init__(self, *args, pinned_ip: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )


def _api_get(url: str, api_key: str = "") -> dict | list:
    """Make a GET request to the API and return parsed JSON.

    Connection is pinned to the IP returned by ``_validate_url`` so the
    actual TCP destination matches the address we validated — no DNS
    rebinding window between validate and connect.
    """
    try:
        resolved_ips = _validate_url(url)
    except LimsUrlValidationError as exc:
        # SSRF / URL-policy refusal. Leave a forensic breadcrumb regardless
        # of who initiated the request — the api-key was about to be sent.
        # Imported lazily to keep this module decoupled from the audit
        # service (which lives in the same services package).
        from .audit_log import audit
        audit(
            "lims.url_blocked",
            actor="lims_client",
            target=url,
            reason=str(exc),
        )
        raise
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    # Prefer IPv4 if any resolved address is IPv4 (broader interop with
    # LIMS hosts behind v4-only middleboxes). Single attempt — operators
    # whose LIMS is multi-IP load-balanced should rely on the LB upstream.
    v4 = [ip for ip in resolved_ips if isinstance(ip, ipaddress.IPv4Address)]
    pinned = v4[0] if v4 else resolved_ips[0]
    pinned_ip = str(pinned)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Per-host throttle, keyed on the validated IP + port (not hostname).
    # Without this canonicalisation an admin who points the LIMS at
    # ``https://10.0.0.5/...`` sometimes and ``https://lims.example.com/...``
    # other times — both resolving to the same target — would get
    # independent budgets and double the outbound rate. Multi-process /
    # multi-replica deployments still need an external load-balancer for
    # global throttling; this key is per-process.
    _throttle(f"{pinned_ip}:{port}")

    headers = {
        "Accept": "application/json",
        "User-Agent": "SeqSetup-SampleAPI",
    }
    if api_key:
        headers["api-key"] = api_key

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if parsed.scheme == "https":
        ssl_context = ssl.create_default_context()
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            host=hostname,
            port=port,
            timeout=30,
            context=ssl_context,
            pinned_ip=pinned_ip,
        )
    else:
        conn = _PinnedHTTPConnection(
            host=hostname,
            port=port,
            timeout=30,
            pinned_ip=pinned_ip,
        )

    try:
        try:
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
        except (socket.error, http.client.HTTPException, ssl.SSLError) as exc:
            raise SampleApiError(f"Network error: {exc}")

        if response.status >= 400:
            raise SampleApiError(f"API error: {response.status} {response.reason}")

        data = response.read(_MAX_RESPONSE_SIZE + 1)
        if len(data) > _MAX_RESPONSE_SIZE:
            raise SampleApiError("API response exceeds maximum size limit")
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            raise SampleApiError("API response is not valid JSON")
    finally:
        conn.close()


def _get_field_value(item: dict, field_name: str, config: SampleApiConfig) -> str:
    """Get a field value from an API response item using field mappings.

    Args:
        item: The API response item (dict).
        field_name: The SeqSetup field name to look up.
        config: API config with field mappings.

    Returns:
        The field value as a string, or empty string if not found.
    """
    # Get the API field name from mappings, or use the SeqSetup field name
    api_field = config.get_api_field(field_name)

    # Try exact match first
    if api_field in item:
        val = item[api_field]
        return str(val).strip()[:_MAX_FIELD_LEN] if val is not None else ""

    # Try case-insensitive match
    lower_item = {k.lower(): v for k, v in item.items()}
    if api_field.lower() in lower_item:
        val = lower_item[api_field.lower()]
        return str(val).strip()[:_MAX_FIELD_LEN] if val is not None else ""

    # Try the original field name as fallback
    if field_name in item:
        val = item[field_name]
        return str(val).strip()[:_MAX_FIELD_LEN] if val is not None else ""
    if field_name.lower() in lower_item:
        val = lower_item[field_name.lower()]
        return str(val).strip()[:_MAX_FIELD_LEN] if val is not None else ""

    return ""


def fetch_worklists(
    config: SampleApiConfig,
    status: Optional[str] = None,
    limit: Optional[int] = None,
    sort_by_date: bool = True,
) -> Tuple[bool, str, list[dict]]:
    """
    Fetch available worksheets from the API.

    Args:
        config: Sample API configuration.
        status: Filter by status (e.g., 'KS' for ready, 'P' for in progress).
        limit: Maximum number of worksheets to return.
        sort_by_date: Sort worksheets by created date (newest first).

    Returns:
        Tuple of (success, message, worksheets)
        where worksheets is a list of dicts with at least 'id' and 'name'.
    """
    if not config.base_url:
        return False, "API base URL is not configured", []

    if not config.enabled:
        return False, "Sample API is not enabled", []

    try:
        url = config.worklists_url(status=status, limit=limit)
        data = _api_get(url, config.effective_api_key())

        # Handle response format: [worksheets_list, pagination_info]
        worksheets_data = data
        if isinstance(data, list) and len(data) == 2:
            if isinstance(data[0], list) and isinstance(data[1], dict):
                worksheets_data = data[0]

        if not isinstance(worksheets_data, list):
            return False, "API response is not a valid format", []

        if len(worksheets_data) == 0:
            return False, "No worksheets available", []

        # Normalize worksheet entries using field mappings
        worksheets = []
        for item in worksheets_data:
            if not isinstance(item, dict):
                continue

            # Get worksheet ID using field mapping (e.g., "AL" -> "worksheet_id")
            wl_id = _get_field_value(item, "worksheet_id", config)
            if not wl_id:
                # Fall back to standard "id" field
                wl_id = _get_field_value(item, "id", config)
            if not wl_id:
                continue

            # Get other fields using mappings
            wl_name = _get_field_value(item, "name", config) or wl_id
            investigator = _get_field_value(item, "investigator", config)
            updated_at = _get_field_value(item, "updated_at", config)

            # Build normalized worksheet entry
            worksheet = {
                "id": wl_id,
                "name": wl_name,
            }
            if investigator:
                worksheet["investigator"] = investigator
            if updated_at:
                worksheet["updated_at"] = updated_at

            # Preserve samples dict if present (for embedded samples format)
            samples_field = config.get_api_field("samples")
            if samples_field in item:
                worksheet["samples"] = item[samples_field]
            elif "samples" in item:
                worksheet["samples"] = item["samples"]

            # Preserve any other fields (lowercased)
            for k, v in item.items():
                lower_k = k.lower()
                if lower_k not in ("id", "name", "samples", "investigator", "updated_at"):
                    # Skip the mapped field names
                    if k not in (config.get_api_field(f) for f in ["worksheet_id", "name", "investigator", "updated_at", "samples"]):
                        worksheet[lower_k] = v

            worksheets.append(worksheet)

        if not worksheets:
            return False, "No valid worksheets found in API response", []

        # Sort by date if requested (newest first)
        if sort_by_date:
            worksheets.sort(key=lambda w: w.get("updated_at", w.get("created", "")), reverse=True)

        logger.info(f"Fetched {len(worksheets)} worksheets from API")
        return True, f"Found {len(worksheets)} worksheets", worksheets

    except SampleApiError as e:
        return False, str(e), []
    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.exception("Worksheet fetch failed")
        return False, msg, []


def check_connection(config: SampleApiConfig) -> Tuple[bool, str]:
    """Test the API connection by calling the worksheets endpoint.

    Unlike fetch_worklists(), this does not require config.enabled to be True,
    since it's used to validate the connection before enabling.

    Returns:
        Tuple of (success, message).
    """
    if not config.base_url:
        return False, "API base URL is not configured"

    try:
        url = config.worklists_url()
        data = _api_get(url, config.effective_api_key())

        # Handle response format: [worksheets_list, pagination_info]
        count = 0
        if isinstance(data, list):
            if len(data) == 2 and isinstance(data[0], list) and isinstance(data[1], dict):
                count = len(data[0])
            else:
                count = len(data)
        else:
            return False, "API response is not a valid format"

        return True, f"Connection successful ({count} worksheets found)"
    except SampleApiError as e:
        return False, str(e)
    except Exception as e:
        logger.exception("Connection test failed")
        return False, f"Unexpected error: {e}"


def fetch_worklist_samples(config: SampleApiConfig, worklist_id: str) -> Tuple[bool, str, list[dict]]:
    """
    Fetch samples for a specific worksheet from the API.

    Args:
        config: Sample API configuration.
        worklist_id: ID of the worksheet to fetch samples for.

    Returns:
        Tuple of (success, message, samples_list)
    """
    if not config.base_url:
        return False, "API base URL is not configured", []

    if not config.enabled:
        return False, "Sample API is not enabled", []

    from ..models.sample_api_config import InvalidWorklistIdError
    try:
        url = config.worklist_samples_url(worklist_id)
    except InvalidWorklistIdError as e:
        return False, str(e), []
    if not url:
        return False, "Could not build samples URL", []

    try:
        data = _api_get(url, config.effective_api_key())

        # Handle different response formats
        samples = []

        if isinstance(data, list):
            # Standard format: array of sample objects
            samples = data
        elif isinstance(data, dict):
            # iGene format: worksheet object with embedded samples
            # Structure: {"AL": "...", "Investigator": "...", "samples": {sample_id: test_id}, ...}
            samples_field = config.get_api_field("samples")

            # Try to find samples in the response
            embedded_samples = None
            if samples_field in data:
                embedded_samples = data[samples_field]
            elif "samples" in data:
                embedded_samples = data["samples"]

            if embedded_samples is not None:
                if isinstance(embedded_samples, dict):
                    # Convert {sample_id: test_id} dict to list of sample objects
                    for sample_id, test_id in embedded_samples.items():
                        samples.append({
                            "sample_id": sample_id,
                            "test_id": test_id if test_id else "",
                            "worksheet_id": worklist_id,
                        })
                elif isinstance(embedded_samples, list):
                    samples = embedded_samples
            else:
                return False, "API response does not contain samples data", []
        else:
            return False, "API response is not a valid format", []

        if len(samples) == 0:
            return False, "Worksheet contains no samples", []

        # Add worksheet_id to each sample if not present
        for s in samples:
            if isinstance(s, dict) and "worksheet_id" not in s:
                s["worksheet_id"] = worklist_id

        logger.info(f"Fetched {len(samples)} samples for worksheet {worklist_id}")
        return True, f"Fetched {len(samples)} samples", samples

    except SampleApiError as e:
        return False, str(e), []
    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.exception("Worksheet samples fetch failed")
        return False, msg, []


def parse_api_samples(data: list[dict], config: Optional[SampleApiConfig] = None) -> list[dict]:
    """
    Parse API response into a normalized list of sample dicts.

    Supports field names matching the paste format conventions:
    sample_id, test_id, worksheet_id, index_i7, index_i5, index_pair_name, i7_name, i5_name

    Also supports custom field mappings via config.field_mappings.

    Args:
        data: List of dicts from API response.
        config: Optional API config with field mappings.

    Returns:
        List of normalized sample dicts with keys:
        sample_id, test_id, worksheet_id, index1_sequence, index2_sequence,
        index_pair_name, index1_name, index2_name
    """
    # Map of normalized field name -> possible API field names
    field_aliases = {
        "sample_id": ["sample_id", "sampleid", "sample", "id", "name", "sample_name"],
        "test_id": ["test_id", "testid", "test", "test_type", "assay", "application"],
        "worksheet_id": ["worksheet_id", "worksheetid", "worksheet", "worklist_id", "al"],
        "index1_sequence": ["index_i7", "index1", "i7", "index_i7_sequence", "i7_sequence"],
        "index2_sequence": ["index_i5", "index2", "i5", "index_i5_sequence", "i5_sequence"],
        "index_pair_name": ["index_pair_name", "pair_name", "index_pair", "index_kit", "kit_name"],
        "index1_name": ["i7_name", "index_i7_name", "index1_name", "index_name"],
        "index2_name": ["i5_name", "index_i5_name", "index2_name"],
    }

    # Add custom field mappings from config
    if config and config.field_mappings:
        for seqsetup_field, api_field in config.field_mappings.items():
            if seqsetup_field in field_aliases:
                # Add the custom mapping to the front of the aliases list
                field_aliases[seqsetup_field] = [api_field.lower()] + field_aliases[seqsetup_field]
            else:
                # New field not in defaults
                field_aliases[seqsetup_field] = [api_field.lower()]

    results = []
    rows_missing_sample_id: list[int] = []  # 1-based positions of dropped rows

    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            rows_missing_sample_id.append(index)
            continue

        # Build a lowercase key lookup
        lower_item = {k.lower(): v for k, v in item.items()}

        sample = {}
        for field, aliases in field_aliases.items():
            for alias in aliases:
                if alias in lower_item and lower_item[alias] is not None:
                    val = lower_item[alias]
                    # Strip + length-clamp per CLAUDE.md input-sanitization rule.
                    # LIMS payloads aren't trusted to honor field widths.
                    sample[field] = str(val).strip()[:_MAX_FIELD_LEN] if val else ""
                    break

        # Must have at least sample_id. Silent skip would route the dropped
        # sample's reads into the demultiplexer's "Undetermined" bucket,
        # making it impossible to report on the patient sample.
        if "sample_id" not in sample or not sample["sample_id"]:
            rows_missing_sample_id.append(index)
            continue

        if len(results) >= MAX_SAMPLES_PER_RUN:
            # Same per-run cap the paste parser enforces — refuse an oversized
            # LIMS worklist rather than building an unbounded list (DoS /
            # 16MB-BSON guard).
            raise ValueError(
                f"Too many samples: a run accepts a maximum of {MAX_SAMPLES_PER_RUN}. "
                f"Reduce the worklist or split it across runs."
            )

        results.append(sample)

    if rows_missing_sample_id:
        rows_str = ", ".join(str(n) for n in rows_missing_sample_id)
        raise ValueError(
            f"LIMS row(s) {rows_str}: sample_id is missing or empty. "
            f"Fix the upstream record(s) before retrying."
        )

    return results
