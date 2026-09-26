"""The docs screenshot run borrows the browser-test database: it saves what
is there, empties it, and must put back exactly what it found."""

import mongomock

from tests.browser.docs_world import clear, restore, snapshot


def test_snapshot_clear_restore_round_trip():
    db = mongomock.MongoClient()["docs_world_test"]
    db["runs"].insert_many([{"_id": "a", "n": 1}, {"_id": "b", "n": 2}])
    db["users"].insert_one({"_id": "u"})

    saved = snapshot(db)
    clear(db)
    assert db["runs"].count_documents({}) == 0
    assert db["users"].count_documents({}) == 0

    db["runs"].insert_one({"_id": "demo"})
    restore(db, saved)

    assert sorted(d["_id"] for d in db["runs"].find()) == ["a", "b"]
    assert [d["_id"] for d in db["users"].find()] == ["u"]
