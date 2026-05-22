"""Repository for API token management."""

import logging
from datetime import datetime
from typing import Optional

import bcrypt
from pymongo.database import Database

from ..models.api_token import ApiToken
from .base import BaseRepository


logger = logging.getLogger(__name__)


# Sentinel bcrypt hash used to ensure verify_token() does at least one
# bcrypt comparison even when no candidate is found. This neutralises the
# timing channel between "wrong-prefix probe" (no bcrypt run) and
# "right-prefix-but-wrong-token" (bcrypt run). Generated at import.
_SENTINEL_HASH = bcrypt.hashpw(b"timing-sentinel-no-token", bcrypt.gensalt(rounds=12))

# Cap on the legacy-fallback scan to prevent DoS via wrong-prefix probes
# triggering O(N) bcrypt operations across every legacy token.
_LEGACY_FALLBACK_SCAN_CAP = 50


class ApiTokenRepository(BaseRepository[ApiToken]):
    """Repository for managing API tokens in MongoDB."""

    COLLECTION = "api_tokens"
    MODEL_CLASS = ApiToken

    def __init__(self, db: Database):
        super().__init__(db)
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create indexes for efficient token lookup."""
        self.collection.create_index("token_prefix", sparse=True)

    def _touch_last_used(self, token: ApiToken) -> None:
        """Best-effort last_used_at update — failures are logged but not raised."""
        try:
            now = datetime.now()
            self.collection.update_one(
                {"_id": token.id},
                {"$set": {"last_used_at": now.isoformat()}},
            )
            token.last_used_at = now
        except Exception:
            logger.warning("Failed to update last_used_at for token %s", token.id, exc_info=True)

    def verify_token(self, plaintext: str) -> Optional[ApiToken]:
        """Verify a plaintext token against stored hashes.

        - Uses token_prefix for fast filtering before expensive bcrypt comparison.
        - Falls back to a CAPPED scan for legacy tokens without a prefix
          (prevents DoS by O(N) bcrypt on wrong-prefix probes).
        - Rejects expired tokens.
        - Always runs at least one bcrypt op even on no-match to neutralise
          the timing side-channel between "no prefix match" and
          "prefix match but wrong token".
        - Updates last_used_at on successful match.
        """
        prefix = plaintext[:8]
        did_bcrypt = False

        # Fast path: tokens whose prefix matches.
        for doc in self.collection.find({"token_prefix": prefix}):
            token = ApiToken.from_dict(doc)
            try:
                did_bcrypt = True
                if token.verify(plaintext) and not token.is_expired():
                    self._touch_last_used(token)
                    return token
            except Exception:
                continue

        # Legacy fallback: tokens without a prefix. Capped to prevent
        # wrong-prefix probes from triggering an unbounded bcrypt scan.
        legacy_query = {"$or": [{"token_prefix": ""}, {"token_prefix": {"$exists": False}}]}
        for doc in self.collection.find(legacy_query).limit(_LEGACY_FALLBACK_SCAN_CAP):
            token = ApiToken.from_dict(doc)
            try:
                did_bcrypt = True
                if token.verify(plaintext) and not token.is_expired():
                    self._touch_last_used(token)
                    return token
            except Exception:
                continue

        # No match. Run a sentinel bcrypt comparison so the response time is
        # comparable to the "candidate found but mismatched" case.
        if not did_bcrypt:
            try:
                bcrypt.checkpw(plaintext.encode("utf-8"), _SENTINEL_HASH)
            except Exception:
                pass
        return None
