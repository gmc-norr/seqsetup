"""FastAPI sub-application for the /api/* surface.

Lives alongside the existing FastHTML app during the framework migration.
Mounted at ``/api`` by ``seqsetup.app``. Owns its own auth dependency and
rate-limit dependency so the FastHTML beforeware is bypassed for API paths.
"""
