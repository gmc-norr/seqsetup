"""Service for fetching worklists and samples from an external API."""

import json
import logging
import urllib.request
import urllib.error
from typing import Tuple

from ..models.sample_api_config import SampleApiConfig

logger = logging.getLogger(__name__)


class SampleApiError(Exception):
    """Error during sample API fetch."""
    pass


def _api_get(url: str, api_key: str = "") -> dict | list:
    """Make a GET request to the API and return parsed JSON."""
    headers = {
        "Accept": "application/json",
        "User-Agent": "SeqSetup-SampleAPI",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SampleApiError(f"API error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise SampleApiError(f"Network error: {e.reason}")
    except json.JSONDecodeError:
        raise SampleApiError("API response is not valid JSON")


def fetch_worklists(config: SampleApiConfig) -> Tuple[bool, str, list[dict]]:
    """
    Fetch available worklists from the API.

    Args:
        config: Sample API configuration.

    Returns:
        Tuple of (success, message, worklists)
        where worklists is a list of dicts with at least 'id' and 'name'.
    """
    if not config.base_url:
        return False, "API base URL is not configured", []

    if not config.enabled:
        return False, "Sample API is not enabled", []

    try:
        data = _api_get(config.worklists_url, config.api_key)

        if not isinstance(data, list):
            return False, "API response is not a JSON array", []

        if len(data) == 0:
            return False, "No worklists available", []

        # Normalize worklist entries - need at least an id
        worklists = []
        for item in data:
            if not isinstance(item, dict):
                continue
            lower_item = {k.lower(): v for k, v in item.items()}
            wl_id = str(lower_item.get("id", "")).strip()
            wl_name = str(lower_item.get("name", "")).strip()
            if not wl_id:
                continue
            worklists.append({
                "id": wl_id,
                "name": wl_name or wl_id,
                **{k: v for k, v in lower_item.items() if k not in ("id", "name")},
            })

        if not worklists:
            return False, "No valid worklists found in API response", []

        logger.info(f"Fetched {len(worklists)} worklists from API")
        return True, f"Found {len(worklists)} worklists", worklists

    except SampleApiError as e:
        return False, str(e), []
    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.exception("Worklist fetch failed")
        return False, msg, []


def check_connection(config: SampleApiConfig) -> Tuple[bool, str]:
    """Test the API connection by calling the worklists endpoint.

    Unlike fetch_worklists(), this does not require config.enabled to be True,
    since it's used to validate the connection before enabling.

    Returns:
        Tuple of (success, message).
    """
    if not config.base_url:
        return False, "API base URL is not configured"

    try:
        data = _api_get(config.worklists_url, config.api_key)
        if not isinstance(data, list):
            return False, "API response is not a JSON array"
        return True, f"Connection successful ({len(data)} worklists found)"
    except SampleApiError as e:
        return False, str(e)
    except Exception as e:
        logger.exception("Connection test failed")
        return False, f"Unexpected error: {e}"


def fetch_worklist_samples(config: SampleApiConfig, worklist_id: str) -> Tuple[bool, str, list[dict]]:
    """
    Fetch samples for a specific worklist from the API.

    Args:
        config: Sample API configuration.
        worklist_id: ID of the worklist to fetch samples for.

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

        if not isinstance(data, list):
            return False, "API response is not a JSON array", []

        if len(data) == 0:
            return False, "Worklist contains no samples", []

        logger.info(f"Fetched {len(data)} samples for worklist {worklist_id}")
        return True, f"Fetched {len(data)} samples", data

    except SampleApiError as e:
        return False, str(e), []
    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.exception("Worklist samples fetch failed")
        return False, msg, []


def parse_api_samples(data: list[dict]) -> list[dict]:
    """
    Parse API response into a normalized list of sample dicts.

    Supports field names matching the paste format conventions:
    sample_id, test_id, index_i7, index_i5, index_pair_name, i7_name, i5_name

    Args:
        data: List of dicts from API response.

    Returns:
        List of normalized sample dicts with keys:
        sample_id, test_id, index1_sequence, index2_sequence,
        index_pair_name, index1_name, index2_name
    """
    # Map of normalized field name -> possible API field names
    field_aliases = {
        "sample_id": ["sample_id", "sampleid", "sample", "id", "name", "sample_name"],
        "test_id": ["test_id", "testid", "test", "test_type", "assay", "application"],
        "index1_sequence": ["index_i7", "index1", "i7", "index_i7_sequence", "i7_sequence"],
        "index2_sequence": ["index_i5", "index2", "i5", "index_i5_sequence", "i5_sequence"],
        "index_pair_name": ["index_pair_name", "pair_name", "index_pair", "index_kit", "kit_name"],
        "index1_name": ["i7_name", "index_i7_name", "index1_name", "index_name"],
        "index2_name": ["i5_name", "index_i5_name", "index2_name"],
    }

    results = []
    for item in data:
        if not isinstance(item, dict):
            continue

        # Build a lowercase key lookup
        lower_item = {k.lower(): v for k, v in item.items()}

        sample = {}
        for field, aliases in field_aliases.items():
            for alias in aliases:
                if alias in lower_item and lower_item[alias]:
                    sample[field] = str(lower_item[alias]).strip()
                    break

        # Must have at least sample_id
        if "sample_id" not in sample or not sample["sample_id"]:
            continue

        results.append(sample)

    return results
