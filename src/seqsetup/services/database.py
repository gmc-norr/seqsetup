"""MongoDB database connection management."""

import logging
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, unquote_plus

import yaml
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, OperationFailure

logger = logging.getLogger(__name__)

# Global database connection
_client: Optional[MongoClient] = None
_db: Optional[Database] = None

# Configuration paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "mongodb.yaml"


# The credential part of a connection URI: everything between the scheme and
# the "@" that ends it.
#
# Two patterns, because the two uses want different appetites. _CONFIGURED is
# anchored at the start of the URI SeqSetup was given, so it may take spaces
# and anything else a password can hold; refusing \s there turned the whole
# scrub off for a password with a space in it, which parse_uri accepts and a
# deployment can therefore have (review of 5aef69b, P2-2). _IN_TEXT scans a
# free-form message, where a greedy run up to a later "@" would swallow
# unrelated words, so it stops at whitespace.
_URI_CREDENTIALS_CONFIGURED = re.compile(r"(mongodb(?:\+srv)?://)([^/@]*)@", re.IGNORECASE)
_URI_CREDENTIALS = re.compile(r"(mongodb(?:\+srv)?://)[^/@\s]*@", re.IGNORECASE)

# A user name shorter than this is not scrubbed from a message: replacing a
# one- or two-letter string everywhere would leave the operator a message of
# asterisks ("a" is in "Authentication"), and a user name is not a secret the
# way a password is. The password is scrubbed whatever its length.
_SHORTEST_NAME_SCRUBBED = 3


def _credentials(uri: str) -> tuple[str, ...]:
    """The user name and password a URI carries, in every form they can be
    written or sent, so a message holding any of them is caught. Longest
    first, so scrubbing the pair does not leave half of one behind.

    Three forms: as the URI writes it, percent-unescaped, and
    ``unquote_plus``-unescaped -- a URI "+" is sent to the server as a space,
    so that is the form the server's own message would carry
    (review of 5aef69b, P2-3).
    """
    match = _URI_CREDENTIALS_CONFIGURED.match(uri or "")
    if not match:
        return ()
    userinfo = match.group(2)
    user, _, password = userinfo.partition(":")
    found = {userinfo}
    for part, shortest in ((password, 1), (user, _SHORTEST_NAME_SCRUBBED)):
        for form in (part, unquote(part), unquote_plus(part)):
            if len(form) >= shortest:
                found.add(form)
    return tuple(sorted((text for text in found if text), key=len, reverse=True))


def _safe(error: BaseException, uri: str) -> str:
    """What may be logged about ``error``: its type, and its message with any
    credentials taken out.

    pymongo's own messages do not echo the URI or the password -- probed over
    InvalidURI, ConfigurationError, ServerSelectionTimeoutError and
    OperationFailure -- but the *server's* errmsg has named the user SeqSetup
    connects as ("Authentication failed on database 'admin' with user 'x'"),
    and anything else in the driver stack may carry the string it was handed.
    Logging ``%s`` of whatever was caught trusted all of them
    (2026-10-18 batch, step 8).
    """
    text = str(error)
    # The configured credentials, in either form, wherever they appear.
    for secret in _credentials(uri):
        text = text.replace(secret, "***")
    # And the credential part of ANY connection string in the message, which
    # may be one SeqSetup was never configured with -- a replica-set member,
    # a redirect, a wrapper repeating a string from elsewhere.
    text = _URI_CREDENTIALS.sub(r"\1***@", text)
    return f"{type(error).__name__}: {text}"


def _yaml_refusal(broken: Exception) -> ValueError:
    """What to raise for a ``config/mongodb.yaml`` that is not YAML: the file
    and the place, never the message.

    PyYAML's message quotes the line it stumbled on, and that line holds the
    connection string -- password included. Measured: it does so for YAML
    given as a *string*, and not for YAML given as an open file, which is how
    this function reads it. So this is a guard rather than a live leak: it
    makes the rule hold whichever way the file is loaded, because reading the
    text first (``yaml.safe_load(f.read())``) is a small-looking change that
    would otherwise put the password in the message.
    """
    mark = getattr(broken, "problem_mark", None) or getattr(broken, "context_mark", None)
    where = (f" at line {mark.line + 1}, column {mark.column + 1}"
             if mark is not None else "")
    return ValueError(
        f"{CONFIG_PATH} could not be read as YAML{where}: "
        f"{type(broken).__name__}. The message is not repeated here: it can "
        f"quote the line, and that line holds the connection string."
    )


def _load_config() -> dict:
    """Load MongoDB configuration from file or environment."""
    # Environment variable takes precedence
    mongo_uri = os.environ.get("MONGODB_URI")
    if mongo_uri:
        return {
            "uri": mongo_uri,
            "database": os.environ.get("MONGODB_DATABASE", "seqsetup"),
        }

    # Fall back to config file
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError as broken:
                raise _yaml_refusal(broken) from None
            return config.get("mongodb", {})

    # Default configuration
    return {
        "uri": "mongodb://localhost:27017",
        "database": "seqsetup",
    }


def init_db() -> Database:
    """Initialize the MongoDB connection."""
    global _client, _db

    if _db is not None:
        return _db

    config = _load_config()
    uri = config.get("uri", "mongodb://localhost:27017")
    database_name = config.get("database", "seqsetup")

    try:
        _client = MongoClient(
            uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            # Bound a single operation that stalls mid-flight on an already-
            # established connection. serverSelectionTimeoutMS/connectTimeoutMS
            # only cover selection + handshake; without socketTimeoutMS a hung
            # op blocks the worker thread (or the event loop) indefinitely.
            socketTimeoutMS=30000,
        )
        # Verify connectivity by pinging the server
        _client.admin.command("ping")
    except ConnectionFailure as e:
        _client = None
        logger.error("Failed to connect to MongoDB: %s", _safe(e, uri))
        raise
    except OperationFailure as e:
        _client = None
        if e.code == 18:  # AuthenticationFailed: say where to look (practice deploy 2026-10-17)
            logger.error(
                "MongoDB refused SeqSetup's user name or password (%s). The "
                "server's own message is not repeated: it has named the user "
                "SeqSetup connects as. With Docker "
                "Compose, MONGO_APP_PASSWORD in .env must be the password "
                "docker/mongo-init.sh created the user with on the first start "
                "(changing .env later does not change it), made only of letters and "
                "digits (openssl rand -hex 24): the connection URI reads a %% and the "
                "two characters after it as one other character, and a + as a space.",
                type(e).__name__)
        else:
            logger.error("Unexpected error connecting to MongoDB: %s", _safe(e, uri))
        raise
    except Exception as e:
        _client = None
        logger.error("Unexpected error connecting to MongoDB: %s", _safe(e, uri))
        raise

    _db = _client[database_name]
    return _db


def get_db() -> Database:
    """Get the current database connection."""
    if _db is None:
        return init_db()
    return _db


def close_db() -> None:
    """Close the database connection."""
    global _client, _db

    if _client is not None:
        _client.close()
        _client = None
        _db = None
