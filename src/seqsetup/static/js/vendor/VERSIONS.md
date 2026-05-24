# Vendored JS

These files are NOT npm/build-tool managed. They're pinned-version
downloads kept in-repo so the app works in air-gapped clinical
deployments and survives external CDN outages.

| File | Source | Version |
|---|---|---|
| htmx.min.js | https://htmx.org/ | 2.0.10 |
| alpine.min.js | https://alpinejs.dev/ | 3.15.12 |

To bump: replace the file, update the version here, run `pixi run smoke-browser`.
