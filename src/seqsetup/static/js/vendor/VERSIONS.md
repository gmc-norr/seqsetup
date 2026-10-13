# Vendored JS

These files are NOT npm/build-tool managed. They're pinned-version
downloads kept in-repo so the app works in air-gapped clinical
deployments and survives external CDN outages.

Every file here is served to the browser. axe-core, which only the
accessibility tests read, is in `tests/browser/vendor/` with its own
VERSIONS.md.

| File | Source | Version | SHA-256 |
|---|---|---|---|
| htmx.min.js | npm `htmx.org`, `dist/htmx.min.js` | 2.0.11 | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| alpine.min.js | npm `alpinejs`, `dist/cdn.min.js` | 3.17.4 | `232519394c6c8fdba6f362b1d9da16106db513cdbf899011f00daab4051df31c` |

To bump: download the package from the npm registry and check it against the
registry's `integrity` hash, copy the file named under Source, update its row
here (`sha256sum` gives the SHA-256), then run `pixi run test` and
`pixi run smoke-browser`. `tests/unit/test_vendored_js.py` fails while a file
and its row disagree.
