## External library dependencies

(PUT INTO AGENTS.md of importing project)

Before writing code that touches any of these libraries, read the linked overview doc.
Do not modify library source unless the task explicitly requires a bug fix there.
Paths in Overview-Doc and API Signatures are relative to Library Root.

| Library | Library Root | Overview-Doc | API Signatures | What it does |
|---|---|---|---|---|
| `encrypted_cache` | `<set to actual path from your project root>` | `doc/AGENTS-OVERVIEW.md` | `doc/AGENTS_api_signatures.txt` | Password-based encrypted on-disk caching for plist-serializable data; `execute_cached()` implements cache-or-compute with TTL and upstream-aware invalidation |
