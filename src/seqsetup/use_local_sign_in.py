"""``pixi run use-local-sign-in``: switch sign-in back to local accounts from
the server (spec 2026-09-28 group 2b, review P2).

With directory sign-in on and local fallback off, a broken directory locks
everyone out. This command is the way back in. The directory settings are
kept, so switching back needs no retyping. "Nothing was changed" is only
said when it is known (plan review 1, P3).
"""

import sys


def main(get_db=None, say=print) -> int:
    """Set the sign-in method to Local and return the exit code."""
    from pymongo.errors import PyMongoError

    from .models.auth_config import AuthMethod
    from .repositories.audit_event_repo import AuditEventRepository
    from .repositories.auth_config_repo import AuthConfigRepository
    from .services.audit_log import audit, set_audit_sink
    from .services.database import init_db

    try:
        db = (get_db or init_db)()
    except Exception:
        say("Could not reach the database. Nothing was changed.")
        return 1
    repo = AuthConfigRepository(db)
    try:
        config = repo.get()
    except PyMongoError as e:
        say(f"The database failed while reading ({type(e).__name__}). Nothing was changed.")
        return 1
    if config.auth_method is AuthMethod.LOCAL:
        say("Sign-in is already local only.")
        return 0
    config.auth_method = AuthMethod.LOCAL
    try:
        repo.save(config)
    except PyMongoError as e:
        # The database may have saved the switch before the answer was lost.
        say(f"The database failed while saving ({type(e).__name__}), so it is not known "
            "whether sign-in was switched to local. Run 'pixi run use-local-sign-in' again: "
            "it says 'Sign-in is already local only.' if the switch was saved.")
        return 1
    set_audit_sink(AuditEventRepository(db))
    audit("auth.method.changed", actor="use-local-sign-in", target="auth_config",
          method=AuthMethod.LOCAL.value, allow_local_fallback=config.allow_local_fallback,
          via="server command")
    say("Sign-in is now local only. The directory settings were kept; switch back on "
        "Admin → Authentication.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
