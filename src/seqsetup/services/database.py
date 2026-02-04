"""MongoDB database connection management."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pymongo import MongoClient
from pymongo.database import Database

# Global database connection
_client: Optional[MongoClient] = None
_db: Optional[Database] = None

# Configuration paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "mongodb.yaml"


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
            config = yaml.safe_load(f)
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

    _client = MongoClient(uri)
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
