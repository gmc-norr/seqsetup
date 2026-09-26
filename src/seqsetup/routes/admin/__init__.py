"""Admin settings routes package.

All admin pages are now in per-page submodules under this package:

  - admin/authentication.py
  - admin/instruments.py
  - admin/sample_api.py
  - admin/logs.py
  - admin/audit.py
  - admin/config_sync.py

Each is included via app.include_router in app.py. There is no
register() function any more — that pattern is fully replaced by
APIRouter + include_router.
"""
