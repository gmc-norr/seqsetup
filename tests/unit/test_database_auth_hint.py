"""When MongoDB refuses SeqSetup's password, the log says where to look.

A practice deploy (2026-10-17) started SeqSetup with a database password
holding %41: docker/mongo-init.sh created the user with it as written, the
connection URI read %41 as "A", and the app restarted for ever with only
"Unexpected error connecting to MongoDB: Authentication failed." in its log
-- while the password in .env looked right.
"""

import logging

import pytest
from pymongo.errors import OperationFailure

from seqsetup.services import database

URI = "mongodb://seqsetup_app:s3cret%41word@mongodb:27017/seqsetup?authSource=seqsetup"


class _Refused:
    """A MongoClient whose server refuses the request with ``code``."""

    def __init__(self, code: int):
        self.code = code

    def __call__(self, *args, **kwargs):
        return self

    @property
    def admin(self):
        return self

    def command(self, name):
        raise OperationFailure("Authentication failed.", code=self.code)


@pytest.fixture
def connecting(monkeypatch):
    monkeypatch.setattr(database, "_client", None)
    monkeypatch.setattr(database, "_db", None)
    monkeypatch.setenv("MONGODB_URI", URI)

    def connect(code: int, caplog) -> str:
        monkeypatch.setattr(database, "MongoClient", _Refused(code))
        with caplog.at_level(logging.ERROR, logger=database.logger.name):
            with pytest.raises(OperationFailure):
                database.init_db()
        return caplog.text

    return connect


class TestARefusedPassword:

    def test_the_log_names_the_password_setting_and_the_characters(self, connecting, caplog):
        log = connecting(18, caplog)
        assert "MONGO_APP_PASSWORD" in log
        assert "openssl rand -hex 24" in log
        assert "first start" in log
        assert "a + as a space" in log

    def test_the_log_never_holds_the_password(self, connecting, caplog):
        log = connecting(18, caplog)
        assert "s3cret" not in log

    def test_the_start_still_stops(self, connecting, caplog):
        connecting(18, caplog)
        assert database._client is None and database._db is None


class TestAnyOtherRefusal:

    def test_is_logged_as_before_without_the_hint(self, connecting, caplog):
        log = connecting(13, caplog)
        assert "Unexpected error connecting to MongoDB" in log
        assert "MONGO_APP_PASSWORD" not in log
