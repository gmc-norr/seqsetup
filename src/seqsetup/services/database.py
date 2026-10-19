"""MongoDB database connection management."""

import logging
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, unquote_plus

from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, OperationFailure

from ..input_rules.database import check_database_file, check_setting
from ..input_rules.problems import problem_line

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


def _refusal(problems) -> ValueError:
    """One refusal naming every error of the settings file, each with its
    line, column and place. No value of the file is in it: the rules build
    every message themselves and scrub the file's own text out of it
    (``input_rules/check.py``, a sensitive input), where PyYAML's own message
    quotes the line it stumbled on -- and that line holds the connection
    string."""
    said = "; ".join(problem_line(p) for p in problems if p.level == "error")
    return ValueError(
        f"{CONFIG_PATH} cannot be used: {said}. No value of the file is "
        f"repeated here: it can hold the connection string."
    )


def _from_the_environment() -> dict:
    """The two variables, whose meaning is unchanged: they win over the file,
    and MONGODB_DATABASE alone still means nothing. Their values go through
    the same rules as the file's, naming the variable where a file's problem
    names a line: a MONGODB_DATABASE holding a '.' reached
    ``_client[name]``, which is outside ``init_db``'s try."""
    settings = {
        "uri": os.environ["MONGODB_URI"],
        "database": os.environ.get("MONGODB_DATABASE", "seqsetup"),
    }
    said = [problem for variable, key in (("MONGODB_URI", "uri"),
                                          ("MONGODB_DATABASE", "database"))
            for problem in check_setting(variable, settings[key])]
    if said:
        raise ValueError(
            "The database settings in the environment cannot be used: "
            + "; ".join(said) + ". No value is repeated here: it can hold the "
            "connection string."
        )
    return settings


def _load_config() -> dict:
    """The connection string and the database name, from the environment or
    from ``config/mongodb.yaml``.

    Three cases, as before: the environment wins; a file that is there must
    be right; and no file at all means the local default. What a file that is
    there says is now checked -- a misspelt ``mongodb:`` key meant
    ``mongodb://localhost:27017``, a different server, without a word
    (docs/design/2026-10-18-input-rules-design.md, step 4).
    """
    if os.environ.get("MONGODB_URI"):
        return _from_the_environment()

    if CONFIG_PATH.exists():
        try:
            text = CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as e:
            raise ValueError(f"{CONFIG_PATH} cannot be read ({e.strerror})") from None
        except UnicodeDecodeError:
            # Not the exception's message: it names a byte of the file and
            # where it is, and that byte can be part of the password.
            raise ValueError(f"{CONFIG_PATH} is not UTF-8 text") from None
        result = check_database_file(text, str(CONFIG_PATH))
        for problem in result.problems:
            if problem.level != "error":
                logger.warning("Database settings: %s", problem_line(problem))
        if not result.ok:
            raise _refusal(result.problems)
        return {"uri": result.value.mongodb.uri, "database": result.value.mongodb.database}

    # No file: the local default, as before.
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
    # Both keys are always there: _load_config builds them from a checked
    # value, from the checked environment, or from the local default. The
    # ``.get`` defaults these two lines had were a second silent fallback to
    # localhost.
    uri = config["uri"]
    database_name = config["database"]

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
