# Parser fixtures

This directory is reserved for larger, sanitized historical responses used by
offline parser and connector regression tests. The current compact canned
RSS/JSON/XML/HTML payloads live inline in `tests/test_smoke.py`; the default test
suite never contacts real sites.

Add a fixture here when a response is too large to keep readable inline, and
add one sample per parser/connector format revision so drift is caught by CI.
Remove credentials, cookies, personal data, and unnecessary copyrighted body
text before committing it. Live-source checks are opt-in with
`INTEL_RUN_LIVE=1 uv run pytest -m live`.
