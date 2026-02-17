"""Service for fetching worksheets and samples from an external API."""

import json
import logging
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse
from typing import Optional, Tuple

from ..models.sample_api_config import SampleApiConfig

logger = logging.getLogger(__name__)

# Maximum API response size (10 MB)
_MAX_RESPONSE_SIZE = 10 * 1024 * 1024


class SampleApiError(Exception):
    """Error during sample API fetch."""
    pass


def _validate_url(url: str) -> None:
    """Validate that a URL is safe to fetch (HTTPS with public hostname)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SampleApiError(f"Unsupported URL scheme: {parsed.scheme}")
    hostname = parsed.hostname or ""
    if not hostname:
        raise SampleApiError("URL has no hostname")
    # Block requests to localhost/private IPs to prevent SSRF
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise SampleApiError(f"Requests to {hostname} are not allowed")


def _api_get(url: str, api_key: str = "") -> dict | list:
    """Make a GET request to the API and return parsed JSON."""
    _validate_url(url)

    headers = {
        "Accept": "application/json",
        "User-Agent": "SeqSetup-SampleAPI",
    }
    if api_key:
        headers["api-key"] = api_key

    request = urllib.request.Request(url, headers=headers)

    # Use default SSL context for certificate verification
    ssl_context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl_context) as response:
            data = response.read(_MAX_RESPONSE_SIZE + 1)
            if len(data) > _MAX_RESPONSE_SIZE:
                raise SampleApiError("API response exceeds maximum size limit")
            return json.loads(data.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SampleApiError(f"API error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise SampleApiError(f"Network error: {e.reason}")
    except json.JSONDecodeError:
        raise SampleApiError("API response is not valid JSON")


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
        return str(val).strip() if val is not None else ""

    # Try case-insensitive match
    lower_item = {k.lower(): v for k, v in item.items()}
    if api_field.lower() in lower_item:
        val = lower_item[api_field.lower()]
        return str(val).strip() if val is not None else ""

    # Try the original field name as fallback
    if field_name in item:
        val = item[field_name]
        return str(val).strip() if val is not None else ""
    if field_name.lower() in lower_item:
        val = lower_item[field_name.lower()]
        return str(val).strip() if val is not None else ""

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
        data = _api_get(url, config.api_key)

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
        data = _api_get(url, config.api_key)

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

    url = config.worklist_samples_url(worklist_id)
    if not url:
        return False, "Could not build samples URL", []

    try:
        data = _api_get(url, config.api_key)

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
    for item in data:
        if not isinstance(item, dict):
            continue

        # Build a lowercase key lookup
        lower_item = {k.lower(): v for k, v in item.items()}

        sample = {}
        for field, aliases in field_aliases.items():
            for alias in aliases:
                if alias in lower_item and lower_item[alias] is not None:
                    val = lower_item[alias]
                    sample[field] = str(val).strip() if val else ""
                    break

        # Must have at least sample_id
        if "sample_id" not in sample or not sample["sample_id"]:
            continue

        results.append(sample)

    return results
