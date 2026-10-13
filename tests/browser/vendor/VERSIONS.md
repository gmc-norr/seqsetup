# Vendored JS for the tests

axe-core is a test tool: the accessibility tests inject it with
`page.evaluate()`, which runs through CDP and is not subject to the page's
CSP. It is kept here, outside `src/seqsetup/static/`, so the app does not
serve half a megabyte of test tool to every browser that asks for it. It is
pinned and in-repo for the same reason as the files the app does serve
(`src/seqsetup/static/js/vendor/VERSIONS.md`): air-gapped clinical
deployments, and CDN outages.

| File | Source | Version | SHA-256 |
|---|---|---|---|
| axe.min.js | npm `axe-core`, `axe.min.js` (accessibility tests only) | 4.9.1 | `182a40dc5d8207e626c09861ad65027d45e85e3a56d01045d068e2e88ee432ea` |

To bump: download the package from the npm registry and check it against the
registry's `integrity` hash, copy the file named under Source, update its row
here (`sha256sum` gives the SHA-256), then run `pixi run test` and
`pixi run smoke-browser`. `tests/unit/test_vendored_js.py` fails while a file
and its row disagree.
