"""Service for fetching worksheets and samples from an external API."""

import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
from types import MappingProxyType
import threading
import time
from collections import Counter
from urllib.parse import urlparse
from typing import Optional, Tuple

from ..models.index import VALID_DNA_RE
from ..models.sample import (
    MAX_SAMPLE_TEXT,
    TEST_VERSION_RE,
    TEST_VERSION_RULE,
    ZERO_SAMPLE_ID_RULE,
    is_zero_only,
    shown_value,
)
from ..models.sample_api_config import (API_KEY_ENV, InvalidWorklistIdError,
                                        SampleApiConfig, validate_worklist_id)
from ..models.sequencing_run import MAX_SAMPLES_PER_RUN
from .sample_parser import _looks_like_index_or_lane

logger = logging.getLogger(__name__)

# Maximum API response size (10 MB)
_MAX_RESPONSE_SIZE = 10 * 1024 * 1024

# Per-field character cap on values extracted from LIMS payloads. Matches the
# 256-char limit applied by form-submission paths so model invariants never
# see an unbounded string regardless of which ingest route was taken. The
# fields below are refused over it instead, never cut, naming their rows: a
# cut ID is another ID (spec 2026-10-14 long sample text), and a cut index
# another index, whose cut could take a character that is not DNA away with
# it (the user's word of 2026-10-20).
_MAX_FIELD_LEN = MAX_SAMPLE_TEXT
_NEVER_CUT = {"sample_id": "the sample_id", "test_id": "the test", "worksheet_id": "the worksheet ID",
              "index1_sequence": "the i7 index", "index2_sequence": "the i5 index"}


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


class LimsAllowedNetsError(ValueError):
    """``SEQSETUP_LIMS_ALLOWED_NETS`` cannot be used as written."""


# The environment variable that lists the networks a LIMS may live on, and
# the one it replaced. The old one switched the whole address check off at
# once -- loopback, every RFC1918 range, CGNAT, and link-local, so a LIMS
# URL could reach 169.254.169.254 and read a cloud host's own credentials.
# The api-key comes from the server's own environment and nowhere else
# (models/sample_api_config.py). A key that holds a control character cannot
# go in a header: http.client raises ValueError("Invalid header value
# b'<the key>\n'"), and that text reached the run page, the admin page, Admin
# > Logs and the container log (review INGEST-1 / SEC-1). A key file's
# trailing newline is the usual cause.
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
API_KEY_REFUSED = (
    "The LIMS API key holds a line break or another control character, so nothing was "
    f"asked of the LIMS. An administrator must set {API_KEY_ENV} again, to the key "
    "alone (see Admin > Sample API). The key itself is not shown anywhere."
)
# What a message says instead of the words http.client puts in its ValueError,
# which quote the header value in full.
HEADER_VALUE_REFUSED = (
    "The request to the LIMS could not be sent: one of its headers holds a character a "
    "header may not carry. No value is shown here."
)

_ALLOWED_NETS_ENV = "SEQSETUP_LIMS_ALLOWED_NETS"
_REMOVED_ALLOW_PRIVATE_NETS_ENV = "SEQSETUP_LIMS_ALLOW_PRIVATE_NETS"

# Networks that no SEQSETUP_LIMS_ALLOWED_NETS entry can open: the four
# categories ``_is_never_allowed_address`` asks ``ipaddress`` about, written
# out as blocks so a listed network can be tested for overlap with them.
# TestTheRefusedRangesMatchPythonsOwnReading checks the two readings agree.
_NEVER_ALLOWED_NETS = tuple(ipaddress.ip_network(text) for text in (
    # link-local -- the host's own link, where cloud instance metadata lives
    "169.254.0.0/16", "fe80::/10",
    # multicast
    "224.0.0.0/4", "ff00::/8",
    # unspecified
    "0.0.0.0/32", "::/128",
    # reserved for future use (IPv4), and IANA's reserved IPv6 blocks
    "240.0.0.0/4",
    "::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4",
    "4000::/3", "6000::/3", "8000::/3", "a000::/3", "c000::/3", "e000::/4",
    "f000::/5", "f800::/6", "fe00::/9",
))


# Loopback is refused unless it is listed, which means the allow-list must
# be able to open it -- and ``::1`` lies inside ``::/8``, so the rules
# above would otherwise refuse the one address there is to list. These are
# the two loopback networks in full: an entry wholly inside one of them is
# an entry for loopback and nothing else.
_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


def _is_never_allowed_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """True for an address no allow-list entry can make reachable.

    Asked of the resolved address, so this holds whatever the operator
    listed: a /8 that happens to contain 169.254.169.254 cannot carry it.

    Loopback is not one of these: it is refused unless the operator listed
    it, which is how a dev setup reaches a mock LIMS on the same host.
    Python reads ``::1`` as reserved (it is inside ``::/8``), so without
    this ``::1`` could not be listed at all and a ``localhost`` that
    resolves to it was unreachable.
    """
    if ip.is_loopback:
        return False
    return ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def _never_allowed_overlap(net):
    """The never-allowed block ``net`` reaches into, or None.

    Any overlap counts, not only a network wholly inside one: the stricter
    reading refuses ``169.0.0.0/8`` rather than letting it stand while the
    address check carries the refusal alone.

    A network wholly inside loopback is the exception, for the reason in
    ``_is_never_allowed_address``: ``::1/128`` may be listed even though it
    is inside the reserved ``::/8``. ``::/8`` itself may not -- it contains
    ``::1`` but does not lie inside it, and it carries the unspecified
    address and the rest of the reserved block with it.
    """
    if any(net.version == loopback.version and net.subnet_of(loopback)
           for loopback in _LOOPBACK_NETS):
        return None
    for block in _NEVER_ALLOWED_NETS:
        if net.version == block.version and net.overlaps(block):
            return block
    return None


def parse_allowed_nets(value: str) -> tuple:
    """``SEQSETUP_LIMS_ALLOWED_NETS`` as networks. Raises LimsAllowedNetsError.

    A comma-separated list of networks in CIDR form, for example
    ``10.0.0.0/8, 127.0.0.1/32``. Empty entries are skipped; anything that
    is not a network (host bits set included) or that reaches into a
    never-allowed block is refused, so the operator hears about it at
    start-up and not when the first worklist import fails.
    """
    nets = []
    for piece in value.split(","):
        text = piece.strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text)
        except ValueError as exc:
            raise LimsAllowedNetsError(
                f"{_ALLOWED_NETS_ENV} entry {text!r} is not a network in CIDR form "
                f"({exc}). Write each network as, for example, 10.0.0.0/8 or "
                f"127.0.0.1/32, separated by commas."
            ) from exc
        block = _never_allowed_overlap(net)
        if block is not None:
            raise LimsAllowedNetsError(
                f"{_ALLOWED_NETS_ENV} entry {text!r} overlaps {block}, which SeqSetup "
                f"never calls a LIMS on: it is link-local (where cloud instance "
                f"metadata lives), multicast, unspecified or reserved. Remove the "
                f"entry or list a narrower network."
            )
        nets.append(net)
    return tuple(nets)


def api_key_is_unusable(api_key: str) -> bool:
    """True when the key cannot be put in a header, so it must not be sent.

    A control character is the usual case (a key file's newline). A character
    outside latin-1 cannot be put in a header either -- http.client encodes a
    header value as latin-1 -- and would otherwise start the app and fail at
    every LIMS call with the vaguer message about a header.
    """
    if _CONTROL_CHARACTER.search(api_key):
        return True
    try:
        api_key.encode("latin-1")
    except UnicodeEncodeError:
        return True
    return False


def check_lims_api_key() -> None:
    """Stop the start when the api-key holds a control character.

    Called from app.py beside the other start-up checks. The message names the
    variable and never its value: it reaches the container log, and the value
    is the secret itself.
    """
    if api_key_is_unusable(os.environ.get(API_KEY_ENV, "")):
        raise RuntimeError(
            f"{API_KEY_ENV} holds a line break or another control character, which "
            f"cannot go in a request header. Set it to the key alone -- a key file's "
            f"own newline is the usual cause. Its value is not shown here."
        )


def check_lims_allowed_nets() -> None:
    """Stop the start when the LIMS network allow-list cannot be used.

    Called from app.py beside the other start-up checks, so a deployment
    hears about a mistyped list before it serves a request. The removed
    variable stops the start whatever it is set to, including an empty
    value: an operator who set it meant to allow something, and silently
    ignoring it would quietly refuse their LIMS instead.
    """
    if _REMOVED_ALLOW_PRIVATE_NETS_ENV in os.environ:
        raise RuntimeError(
            f"{_REMOVED_ALLOW_PRIVATE_NETS_ENV} is no longer used: it allowed every "
            f"private address at once, link-local included. List the networks your "
            f"LIMS is on in {_ALLOWED_NETS_ENV} instead, as comma-separated CIDR "
            f"(for example {_ALLOWED_NETS_ENV}=10.0.0.0/8), and unset "
            f"{_REMOVED_ALLOW_PRIVATE_NETS_ENV}."
        )
    try:
        parse_allowed_nets(os.environ.get(_ALLOWED_NETS_ENV, ""))
    except LimsAllowedNetsError as exc:
        raise RuntimeError(str(exc)) from exc


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
       after DNS resolution. An operator whose LIMS lives on one of those
       networks lists it in ``SEQSETUP_LIMS_ALLOWED_NETS`` (comma-separated
       CIDR) — a deliberate per-deployment decision that opens the listed
       networks and nothing else, not the pinning that follows. A
       link-local, multicast, unspecified or reserved address stays refused
       however it is listed (``_is_never_allowed_address``).
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

    try:
        allowed_nets = parse_allowed_nets(os.environ.get(_ALLOWED_NETS_ENV, ""))
    except LimsAllowedNetsError as exc:
        # check_lims_allowed_nets() stops the start on this, so reaching it
        # here means the value changed under a running process. Fail closed.
        raise LimsUrlValidationError(str(exc)) from exc
    for ip in resolved:
        if not _is_private_address(ip):
            continue
        if _is_never_allowed_address(ip):
            raise LimsUrlValidationError(
                f"Refusing to call LIMS at {hostname!r} ({ip}): address is "
                f"loopback/private/link-local/CGNAT — link-local, multicast, "
                f"unspecified and reserved addresses are refused whatever "
                f"{_ALLOWED_NETS_ENV} lists, because they point at the host's own "
                f"link (cloud instance metadata) rather than at a LIMS."
            )
        if not any(ip in net for net in allowed_nets):
            raise LimsUrlValidationError(
                f"Refusing to call LIMS at {hostname!r} ({ip}): address is "
                f"loopback/private/link-local/CGNAT. SSRF is blocked by policy. "
                f"For a corporate-network LIMS, or a mock LIMS in dev, list the "
                f"network it is on in {_ALLOWED_NETS_ENV} (comma-separated CIDR, "
                f"for example {_ALLOWED_NETS_ENV}=10.0.0.0/8)."
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


def _refuse_a_repeated_name(pairs: list) -> dict:
    """One JSON object of a LIMS reply: a name twice is refused, never
    resolved; json.loads would keep the last and lose a patient's row (spec
    2026-10-10 later list slice 1, §1)."""
    seen = set()
    for name, _value in pairs:
        if name in seen:
            raise SampleApiError(
                f"The LIMS reply has the name {shown_value(name)!r} twice in one object. "
                f"SeqSetup cannot tell which value is right, so the reply was not used."
            )
        seen.add(name)
    return dict(pairs)


def _api_get(url: str, api_key: str = "") -> dict | list:
    """Make a GET request to the API and return parsed JSON.

    Connection is pinned to the IP returned by ``_validate_url`` so the
    actual TCP destination matches the address we validated — no DNS
    rebinding window between validate and connect.
    """
    # Before anything leaves this machine: a key that cannot go in a header is
    # not sent, and the refusal names no value.
    if api_key and api_key_is_unusable(api_key):
        raise SampleApiError(API_KEY_REFUSED)
    try:
        resolved_ips = _validate_url(url)
    except LimsUrlValidationError as exc:
        # SSRF / URL-policy refusal. Leave a forensic breadcrumb regardless
        # of who initiated the request — the api-key was about to be sent.
        # Imported lazily to keep this module decoupled from the audit
        # service (which lives in the same services package).
        from .audit_log import audit, redact_url
        audit(
            "lims.url_blocked",
            actor="lims_client",
            target=redact_url(url),
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
        except ValueError:
            # http.client quotes the offending header value in its message, so
            # neither it nor the exception it came from is passed on (`from
            # None`: a logger.exception higher up would print the chain).
            raise SampleApiError(HEADER_VALUE_REFUSED) from None

        if response.status >= 400:
            raise SampleApiError(f"API error: {response.status} {response.reason}")

        data = response.read(_MAX_RESPONSE_SIZE + 1)
        if len(data) > _MAX_RESPONSE_SIZE:
            raise SampleApiError("API response exceeds maximum size limit")
        try:
            return json.loads(data.decode("utf-8"), object_pairs_hook=_refuse_a_repeated_name)
        except json.JSONDecodeError:
            raise SampleApiError("API response is not valid JSON")
    finally:
        conn.close()


def _raw_field_value(item: dict, field_name: str, config: SampleApiConfig):
    """A field's value as the API sent it, found by the field mappings: the
    mapped name, then in any capitals, then the SeqSetup name the same two
    ways. None if not found."""
    # Get the API field name from mappings, or use the SeqSetup field name
    api_field = config.get_api_field(field_name)

    # Try exact match first
    if api_field in item:
        return item[api_field]

    # Try case-insensitive match
    lower_item = {k.lower(): v for k, v in item.items()}
    if api_field.lower() in lower_item:
        return lower_item[api_field.lower()]

    # Try the original field name as fallback
    if field_name in item:
        return item[field_name]
    if field_name.lower() in lower_item:
        return lower_item[field_name.lower()]

    return None


def _get_field_value(item: dict, field_name: str, config: SampleApiConfig) -> str:
    """Get a field value from an API response item using field mappings.

    Args:
        item: The API response item (dict).
        field_name: The SeqSetup field name to look up.
        config: API config with field mappings.

    Returns:
        The field value as a string, or empty string if not found.
    """
    val = _raw_field_value(item, field_name, config)
    return str(val).strip()[:_MAX_FIELD_LEN] if val is not None else ""


def _worksheet_id(item: dict, config: SampleApiConfig) -> str:
    """A worksheet's ID in the LIMS list: the worksheet ID field, or id when
    that is absent, null or blank. ValueError when two names of the item are
    one of those names once lower-cased, or when the ID read is not text or a
    whole number: str() would read JSON 25.10 as "25.1", and the import would
    fetch that other worksheet (spec 2026-10-10 later list slice 2, §3). The
    ID is used as sent: one the import could not ask the LIMS for as it is,
    with spaces around it for one, is a ValueError too; stripped, " W2 " was
    listed as W2 and fetched worksheet W2 (build review of slice 2, E-3)."""
    names = {name.lower() for name in (config.get_api_field("worksheet_id"), "worksheet_id", "id")}
    first_spelling: dict = {}
    for key in item:
        lower = key.lower()
        if lower not in names:
            continue
        if lower in first_spelling:
            raise ValueError(
                f"A worksheet in the LIMS list has the names {shown_value(first_spelling[lower])!r} "
                f"and {shown_value(key)!r}, which SeqSetup reads as one name. Send only one of them."
            )
        first_spelling[lower] = key
    raw = _raw_field_value(item, "worksheet_id", config)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raw = _raw_field_value(item, "id", config)
    _refuse_a_changed_value("A worksheet in the LIMS list has an ID", raw)
    if raw is None or not str(raw).strip():
        return ""
    text = str(raw)
    try:
        validate_worklist_id(text)
    except InvalidWorklistIdError:
        raise ValueError(
            f"A worksheet in the LIMS list has the ID {shown_value(text)!r}, which SeqSetup cannot "
            f"ask the LIMS for as it was sent: an ID is at most 128 letters, digits, '.', '_', '-' "
            f"or '~', with no spaces, and not made only of dots."
        )
    return text


def _read_worksheets(worksheets_data: list, config: SampleApiConfig) -> Tuple[list[dict], list[str]]:
    """The worksheets of a LIMS list, as a run lists them, and the warnings
    for the entries left out. The list and the admin's connection check
    both read it so (build review of later list slice 2, MB-6)."""
    # Normalize worksheet entries using field mappings
    worksheets = []
    left_out = []
    for item in worksheets_data:
        if not isinstance(item, dict):
            # Dropped with no warning (build review of later list slice 2, M1-5).
            left_out.append(
                f"An entry in the LIMS list is not a worksheet "
                f"({shown_value(json.dumps(item))}). It is left out of the list."
            )
            continue

        # Get worksheet ID using field mapping (e.g., "AL" -> "worksheet_id"),
        # else the standard "id" field
        try:
            wl_id = _worksheet_id(item, config)
        except ValueError as e:
            left_out.append(f"{e} It is left out of the list.")
            continue
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

    # Two worksheets with one ID would be two options that fetch the same
    # worksheet, one under the other's label (build review of slice 2, E-3).
    counts = Counter(w["id"] for w in worksheets)
    for wl_id in [i for i in counts if counts[i] > 1]:
        left_out.append(
            f"{counts[wl_id]} worksheets in the LIMS list have the ID {shown_value(wl_id)!r}, and "
            f"SeqSetup cannot tell which one the LIMS means. They are left out of the list."
        )
    worksheets = [w for w in worksheets if counts[w["id"]] == 1]
    return worksheets, left_out


def fetch_worklists(
    config: SampleApiConfig,
    status: Optional[str] = None,
    limit: Optional[int] = None,
    sort_by_date: bool = True,
) -> Tuple[bool, str, list[dict], list[str]]:
    """
    Fetch available worksheets from the API.

    Args:
        config: Sample API configuration.
        status: Filter by status (e.g., 'KS' for ready, 'P' for in progress).
        limit: Maximum number of worksheets to return.
        sort_by_date: Sort worksheets by created date (newest first).

    Returns:
        Tuple of (success, message, worksheets, left_out)
        where worksheets is a list of dicts with at least 'id' and 'name',
        and left_out the warnings for worksheets left out of the list.
    """
    if not config.base_url:
        return False, "API base URL is not configured", [], []

    if not config.enabled:
        return False, "Sample API is not enabled", [], []

    try:
        url = config.worklists_url(status=status, limit=limit)
        data = _api_get(url, config.effective_api_key())

        # Handle response format: [worksheets_list, pagination_info]
        worksheets_data = data
        pagination: dict = {}
        if isinstance(data, list) and len(data) == 2:
            if isinstance(data[0], list) and isinstance(data[1], dict):
                worksheets_data, pagination = data[0], data[1]

        if not isinstance(worksheets_data, list):
            return False, "API response is not a valid format", [], []

        total = pagination.get("total")
        has_total = isinstance(total, int) and not isinstance(total, bool)
        if len(worksheets_data) == 0:
            return False, "No worksheets available", [], (
                [f"The LIMS reports {total} worksheets but sent none."]
                if has_total and total > 0 else [])

        worksheets, left_out = _read_worksheets(worksheets_data, config)
        # One page is asked for and one page is read: when the LIMS says it
        # has more than it sent, the list says so rather than looking whole
        # (review INGEST-2).
        if has_total and total > len(worksheets_data):
            # First, not last: the page shows ten warnings and counts the rest
            # (routes/samples.py), and this is the one that must not be the
            # one cut (fresh review of this branch, Important 2).
            left_out.insert(
                0,
                f"The LIMS has {total} worksheets and sent {len(worksheets_data)} of them: "
                f"the rest are not in this list. Ask the laboratory system to close or "
                f"archive the worksheets this run does not need."
            )

        if not worksheets:
            return False, "No valid worksheets found in API response", [], left_out

        # Sort by date if requested (newest first)
        if sort_by_date:
            # As text: a created value that is not text stopped the sort (build
            # review of later list slice 2, M1-4).
            worksheets.sort(key=lambda w: str(w.get("updated_at", w.get("created", ""))),
                            reverse=True)

        logger.info(f"Fetched {len(worksheets)} worksheets from API")
        return True, f"Found {len(worksheets)} worksheets", worksheets, left_out

    except SampleApiError as e:
        return False, str(e), [], []
    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.exception("Worksheet fetch failed")
        return False, msg, [], []


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
        if not isinstance(data, list):
            return False, "API response is not a valid format"
        entries = data
        if len(data) == 2 and isinstance(data[0], list) and isinstance(data[1], dict):
            entries = data[0]

        # Counted as a run lists them (build review of later list slice 2, MB-6).
        worksheets, _left_out = _read_worksheets(entries, config)
        unlisted = len(entries) - len(worksheets)
        if unlisted:
            return True, (f"Connection successful ({len(worksheets)} worksheets found; "
                          f"{unlisted} other entries in the reply are not listed)")
        return True, f"Connection successful ({len(worksheets)} worksheets found)"
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
                        # The test as sent, so parse_api_samples checks it by
                        # its JSON type (spec 2026-10-07 group A4, §2).
                        samples.append({
                            "sample_id": sample_id,
                            "test_id": test_id if test_id is not None else "",
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

        # Add worksheet_id to a sample only when it has none under a name the
        # import reads it from, in any capitals: parse_api_samples refuses two
        # spellings of one name, so it must see only names the LIMS sent (spec
        # 2026-10-10 later list slice 1, §1), and beside the row's own
        # worklist_id or AL it hid that one (Astra's review of slice 2).
        names = set(_SAMPLE_WORKSHEET_ID_NAMES) | {config.get_api_field("worksheet_id").lower()}
        for s in samples:
            if isinstance(s, dict) and not any(
                    isinstance(k, str) and k.lower() in names for k in s):
                s["worksheet_id"] = worklist_id

        logger.info(f"Fetched {len(samples)} samples for worksheet {worklist_id}")
        return True, f"Fetched {len(samples)} samples", samples

    except SampleApiError as e:
        return False, str(e), []
    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.exception("Worksheet samples fetch failed")
        return False, msg, []


def name_list(ids: list[str], limit: int = 10) -> str:
    """'A, B, C' — the first ``limit`` names, then 'and N more'."""
    shown = ", ".join(ids[:limit])
    return f"{shown} and {len(ids) - limit} more" if len(ids) > limit else shown


def _lims_test_version(sample_id: str, value) -> str:
    """A LIMS sample's test version, by its JSON type, before anything turns
    it into text: str() would read JSON 1.10 as "1.1" and drop a 0 (spec
    2026-10-07 group A4, §2). Never cut. ValueError names the sample."""
    if value is None:
        return ""
    if isinstance(value, float):
        raise ValueError(
            f"Sample '{sample_id}' has a test version that is a number with a decimal point "
            f"({value!r}), which JSON may have changed (1.10 is read as 1.1). Send it as text, "
            f'for example "1.10".'
        )
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(
            f"Sample '{sample_id}' has a test version that is not text or a whole number "
            f"({shown_value(json.dumps(value))})."
        )
    text = str(value).strip()
    if text and not TEST_VERSION_RE.match(text):
        raise ValueError(
            f"Sample '{sample_id}' has a test version that is not right ({shown_value(text)!r}). "
            f"{TEST_VERSION_RULE}."
        )
    return text


def _refuse_a_changed_value(what: str, value) -> None:
    """A value read from a LIMS row, by its JSON type: str() would read JSON
    23.10 as "23.1", true as "True" and a list as "['a']", so these are
    refused, never changed (spec 2026-10-07 group A4, §2, decision 12; spec
    2026-10-10 later list slice 1, §1). Text, whole numbers and None (a
    value that is absent or null) pass."""
    if value is None or isinstance(value, str):
        return
    if isinstance(value, float):
        raise ValueError(
            f"{what} that is a number with a decimal point ({value!r}), which JSON may have "
            f'changed (1.10 is read as 1.1). Send it as text, for example "1.10".'
        )
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{what} that is not text or a whole number ({shown_value(json.dumps(value))})."
        )


# The names a LIMS sample row's worksheet ID is read from, before an admin's
# mapped name; fetch_worklist_samples adds the picked worksheet only to a row
# with none of them.
_SAMPLE_WORKSHEET_ID_NAMES = ("worksheet_id", "worksheetid", "worksheet", "worklist_id", "al")

# The names an i7 and an i5 sequence are read from, before an admin's mapped
# name; in this order in the message that refuses a field it does not read.
_I7_NAMES = ("index_i7", "index1", "i7", "index_i7_sequence", "i7_sequence")
_I5_NAMES = ("index_i5", "index2", "i5", "index_i5_sequence", "i5_sequence")

# Each field the import reads, and the field names a LIMS may send it under,
# in the order they are looked for. A module constant so a test can walk it:
# the same table it has always been, read from here instead of built inside
# parse_api_samples (step 5 of the input rules; the only change it makes in
# src/, and it changes no behaviour).
# Tuples behind a read-only view: which LIMS field becomes a sample ID is
# not something a caller or a test may rewire (fresh review of the step 5
# design, P3-8).
ALIAS_NAMES = MappingProxyType({
    "sample_id": ("sample_id", "sampleid", "sample", "id", "name", "sample_name"),
    "test_id": ("test_id", "testid", "test", "test_type", "assay", "application"),
    # Not "version" alone: another field may have that name (spec
    # 2026-10-07 group A4, §2).
    "test_version": ("test_version", "testversion"),
    "worksheet_id": tuple(_SAMPLE_WORKSHEET_ID_NAMES),
    "index1_sequence": tuple(_I7_NAMES),
    "index2_sequence": tuple(_I5_NAMES),
    "index_pair_name": ("index_pair_name", "pair_name", "index_pair", "index_kit",
                        "kit_name"),
    "index1_name": ("i7_name", "index_i7_name", "index1_name", "index_name"),
    "index2_name": ("i5_name", "index_i5_name", "index2_name"),
})


def _unread_fields_error(fields: dict[str, list[int]]) -> ValueError:
    """Reject the whole worklist: a field looks like an index or a lane but
    is not one SeqSetup reads (index mix-up audit, 2026-10-14; the user's
    choice "Same rules as paste")."""
    rows = ", ".join(str(n) for n in sorted({row for found in fields.values() for row in found}))
    quoted = ", ".join(f'"{shown_value(name)}"' for name in fields)
    lanes = any(word.startswith("lane")
                for name in fields for word in re.split(r"[^a-z0-9]+", name.lower()))
    return ValueError(
        f"LIMS row(s) {rows}: the field(s) {quoted} look like an index or a lane, but SeqSetup "
        f"does not read them, so the whole worklist was refused. It reads the i7 from "
        f"{', '.join(_I7_NAMES[:-1])} or {_I7_NAMES[-1]}, and the i5 from "
        f"{', '.join(_I5_NAMES[:-1])} or {_I5_NAMES[-1]}."
        + (" Lanes come from the Lanes picker on the import, not from the LIMS." if lanes else "")
        + " Rename or remove the field(s) in the LIMS."
    )


# How a message names a sample field read from a LIMS row; the fields checked
# by their JSON type (spec 2026-10-10 later list slice 1, §1). The test and
# its version have their own checks; worksheet fields an admin maps are not
# checked.
_FIELD_LABELS = {
    "sample_id": "a sample ID",
    "worksheet_id": "a worksheet ID",
    "index1_sequence": "an i7 sequence",
    "index2_sequence": "an i5 sequence",
    "index_pair_name": "an index name",
    "index1_name": "an i7 name",
    "index2_name": "an i5 name",
}

# The fields that hold a sample's indexes: each may come under one name only.
_INDEX_FIELDS = ("index1_sequence", "index2_sequence", "index_pair_name", "index1_name",
                 "index2_name")


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
    field_aliases = {field: list(names) for field, names in ALIAS_NAMES.items()}

    # The import's own sample fields; an admin's other mappings (investigator,
    # updated_at, samples) name worksheet fields, which a sample row does not
    # use (spec 2026-10-10 later list slice 1, §1).
    sample_fields = set(field_aliases)

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
    rows_zero_sample_id: list[int] = []  # 1-based positions of rows named only 0
    rows_too_long: dict[str, list[int]] = {field: [] for field in _NEVER_CUT}
    read_names = {alias for field in sample_fields for alias in field_aliases[field]}
    unread_fields: dict[str, list[int]] = {}

    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            rows_missing_sample_id.append(index)
            continue

        # A field that looks like an index or a lane must be one SeqSetup
        # reads: "index" (Illumina's name for the i7) was dropped, and the
        # sample came in with only its i5 (index mix-up audit, 2026-10-14).
        for name in item:
            if name.lower() not in read_names and _looks_like_index_or_lane(name):
                unread_fields.setdefault(name, []).append(index)

        # Two names SeqSetup reads that differ only in capitals would be read
        # as one, and one value lost (spec 2026-10-10 later list slice 1, §1).
        first_spelling = {}
        for name in item:
            lower = name.lower()
            if lower not in read_names:
                continue
            if lower in first_spelling:
                raise ValueError(
                    f"LIMS row {index} has the names {shown_value(first_spelling[lower])!r} and "
                    f"{shown_value(name)!r}, which SeqSetup reads as one name. "
                    f"Send only one of them."
                )
            first_spelling[lower] = name

        # Two names for one index would be read as one, the other dropped
        # without a word — an empty first one left the sample with no i7; the
        # paste refuses a second column for it (review of 69d910a).
        for field in _INDEX_FIELDS:
            names = [name for name in item if name.lower() in field_aliases[field]]
            if len(names) > 1:
                quoted = ", ".join(f'"{shown_value(name)}"' for name in names)
                raise ValueError(
                    f"LIMS row {index} has more than one name for {_FIELD_LABELS[field]} "
                    f"({quoted}), so the whole worklist was refused: SeqSetup would read only "
                    f"one of them. Send only one."
                )

        # Build a lowercase key lookup
        lower_item = {k.lower(): v for k, v in item.items()}

        sample = {}
        for field, aliases in field_aliases.items():
            for alias in aliases:
                if alias in lower_item and lower_item[alias] is not None:
                    val = lower_item[alias]
                    label = _FIELD_LABELS.get(field)
                    if label:
                        _refuse_a_changed_value(f"LIMS row {index} has {label}", val)
                    # Strip + length-clamp per CLAUDE.md input-sanitization rule.
                    # LIMS payloads aren't trusted to honor field widths.
                    text = str(val).strip()
                    sample[field] = text if field in _NEVER_CUT else text[:_MAX_FIELD_LEN]
                    break

        # Must have at least sample_id. Silent skip would route the dropped
        # sample's reads into the demultiplexer's "Undetermined" bucket,
        # making it impossible to report on the patient sample.
        if "sample_id" not in sample or not sample["sample_id"]:
            rows_missing_sample_id.append(index)
            continue

        # An empty well a LIMS calls 0, sent as the number 0 or as text. The
        # model refuses it, so the whole worklist is refused here — naming
        # its rows, like a row with no sample ID at all.
        if is_zero_only(sample["sample_id"]):
            rows_zero_sample_id.append(index)
            continue

        # The sample ID first: the messages below name it. The test after its
        # own check, so a test that is not text is called that, not long.
        if len(sample["sample_id"]) > MAX_SAMPLE_TEXT:
            rows_too_long["sample_id"].append(index)
            continue

        # A null name gives way to the next one, as for every field above.
        raw_test = next((lower_item[alias] for alias in field_aliases["test_id"]
                         if lower_item.get(alias) is not None), None)
        _refuse_a_changed_value(f"Sample '{sample['sample_id']}' has a test", raw_test)
        too_long = [field for field in ("test_id", "worksheet_id", "index1_sequence",
                                        "index2_sequence")
                    if len(sample.get(field, "")) > MAX_SAMPLE_TEXT]
        if too_long:
            for field in too_long:
                rows_too_long[field].append(index)
            continue
        raw_version = next((lower_item[alias] for alias in field_aliases["test_version"]
                            if lower_item.get(alias) is not None), None)
        sample["test_version"] = _lims_test_version(sample["sample_id"], raw_version)
        # A test and its version are set together (spec 2026-10-07 group A4, §2).
        if sample["test_version"] and not sample.get("test_id"):
            raise ValueError(f"Sample '{sample['sample_id']}' has a test version but no test.")

        # Index sequences must be DNA — uppercase + validate here, naming the
        # sample, instead of letting Index() raise an opaque 500 downstream.
        for seq_field in ("index1_sequence", "index2_sequence"):
            seq = sample.get(seq_field)
            if seq:
                upper = seq.upper()
                if not VALID_DNA_RE.match(upper):
                    bad = "".join(sorted(set(upper) - set("ACGTN")))
                    raise ValueError(
                        f"Sample '{sample['sample_id']}' has an invalid {seq_field} "
                        f"('{seq}'): only A, C, G, T, N are allowed (offending: {bad})."
                    )
                sample[seq_field] = upper

        if len(results) >= MAX_SAMPLES_PER_RUN:
            # Same per-run cap the paste parser enforces — refuse an oversized
            # LIMS worklist rather than building an unbounded list (DoS /
            # 16MB-BSON guard).
            raise ValueError(
                f"Too many samples: a run accepts a maximum of {MAX_SAMPLES_PER_RUN}. "
                f"Reduce the worklist or split it across runs."
            )

        results.append(sample)

    if unread_fields:
        raise _unread_fields_error(unread_fields)
    if rows_missing_sample_id:
        rows_str = ", ".join(str(n) for n in rows_missing_sample_id)
        raise ValueError(
            f"LIMS row(s) {rows_str}: sample_id is missing or empty. "
            f"Fix the upstream record(s) before retrying."
        )

    if rows_zero_sample_id:
        rows_str = ", ".join(str(n) for n in rows_zero_sample_id)
        raise ValueError(
            f"LIMS row(s) {rows_str}: {ZERO_SAMPLE_ID_RULE}. "
            f"Fix the upstream record(s) before retrying."
        )

    for field, what in _NEVER_CUT.items():
        if rows_too_long[field]:
            rows_str = ", ".join(str(n) for n in rows_too_long[field])
            raise ValueError(
                f"LIMS row(s) {rows_str}: {what} is longer than {MAX_SAMPLE_TEXT} characters. "
                f"SeqSetup does not shorten it. Fix the upstream record(s) before retrying."
            )

    # One sample ID twice: SeqSetup cannot tell which row is right, so the
    # whole worklist is refused, like a paste (review DI-01; spec
    # 2026-10-03 group A1, §3).
    ids = [s["sample_id"] for s in results]
    counts = Counter(ids)
    repeated = [sid for sid in dict.fromkeys(ids) if counts[sid] > 1]
    if repeated:
        raise ValueError(
            "these sample IDs appear more than once in the worklist: "
            f"{name_list(repeated)}. Nothing was added."
        )

    return results
