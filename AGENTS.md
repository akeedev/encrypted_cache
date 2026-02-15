# AGENTS.md — Coding Agent Instructions

You are an expert in Python, Unix shell, and in writing scalable software architectures for finance. You write secure, maintainable, and performant code following best practices. This is a general, non-project specific set of coding guidelines.


## Session start checklist
- Read this file (AGENTS.md)
- Read spec/000-overview.md, spec/010-architecture.md, spec/020-components.md if available
- Read SESSION.md to continue from where you left off last time.


## Workflow
- We work spec-first. Before implementing, read:
  - $PROJECT_DIR$/spec/000-overview.md and spec/010-architecture.md
  - when available the current general feature spec under $PROJECT_DIR$/spec/NNN-*.md (I will name it).
  - or when available the current component feature spec under $PROJECT_DIR$/spec/component/component-NNN-*.md (I will name it).
  - Specs named `rfeat-NNN-*.md` are features reverse-engineered from existing code (not written upfront).
- When drafting a spec, include if useful:
  - A brief target-behavior checklist (what should work when done).
  - Required demo scenarios (e.g., unlock-on-request vs unlock-all).
  - Prompt location notes for any user interaction (daemon terminal vs notebook/client).
  - Explicit defaults that impact UX (timeouts, retries, auto-init).
  - A short list of assumptions for confirmation.


## Version control
- We want the git main branch always to be deployable. Hence, we use GitHub Flow
- Create a new git branch for each feature, and also when doing bugfixes
- Commit often, with clear commit messages, but ask me for confirmation.
- Don't push. I will review your code and merge it into master.



## General
- The project values clarity over cleverness, optimize for readability and maintainability; aim for clarity and a pleasant reading experience.
- Prefer small, reviewable, incremental changes. Keep diffs minimal.
- Do not introduce new dependencies unless necessary.
- When you need libraries, explain to me and ask me what to use
- If there's an established library available for requested behavior, suggest that we use it, but let me review
- Follow existing architecture and naming conventions.
- Respect locked code sections. Any section starting with `# <LOCKED CODE` and ending with `# </LOCKED CODE>` is read-only and must usually not be edited by AI agents. Treat such sections as a code template given by me and try to respect their structure, also in other code. If changes are needed inside locked sections, pause and ask for a resolution.
- Notebooks: treat any cell containing a line that starts with `# <LOCKED CODE` as read-only; do not edit that cell unless you ask for and receive explicit permission. Especially in notebooks, such cells usually contain code examples that demonstrate how I would like the code to work. Take these as a guideline for the design of classes and functions.
- Primary project language is Python, version >= 3.12
- Each feature spec should include a module overview section with planned modules/classes, main functions, and lifecycle notes when applicable.


## Build
- Keep runtime dependencies minimal; move dev tools to `dependency-groups.dev`.
- Environment is setup via uv, use uv for running code, tests, etc.
- Setup according pyproject.toml files for use with uv
- When updating install docs, include both `pip` and `uv pip` commands.


## Legal matters
- Copyright and authorship: **@drakee**. Use this in all copyright lines and Author metadata fields.
- The project will be open source, so we can use open source libraries.
- Eventually, the project will be shared on github.
- Preserve and update project legal notices (LICENSE/NOTICE/README/CONTRIBUTING) when changes affect them.


## Project file structure
- get project feature descriptions from $PROJECT_DIR$/spec
- put Tests into $PROJECT_DIR$/tests
- put Sources into $PROJECT_DIR$/src
- put input data, work data, output data into $PROJECT_DIR$/data
- put test datasets into $PROJECT_DIR$/testdata
- Maintain documentation in `doc/` for user-facing changes (overview + user guide + MVP checklist).
- put documentation into $PROJECT_DIR$/doc
- clone vendor contributions by git into $PROJECT_DIR$/vendor as git submodules, but ask me first


## Language and style
- Write all code identifiers and comments in English.
- use descriptive variable names and comments.
- comment what adds value and not what is obvious from symbol names and code
- Prefer clear, explicit code over cleverness.


## Workflow and IDE
- Locate symbols via IDE navigation / find usages when available.
- Rely on project symbols from IDE where possible, read files only when needed
- Prefer IDE refactorings (Rename/Move) over manual search/replace.
- Create Jetbrains run configurations for uv-based running, pytest, mypy and linting.


## Python specifics
- **`Path.with_suffix()` footgun:** `Path.with_suffix(".ext")` *replaces* the existing suffix, it does
  not append.  To add a suffix only when none exists, use `if not path.suffix: path = path.with_suffix(...)`.
  Never silently replace a user-provided file extension.
- Error handling: fail fast with clear exceptions; use assertions; avoid silent fallbacks.
- Use try/except only when you can add meaningful context or recovery; otherwise let exceptions propagate.
- When operations are likely to fail (filesystem, sockets, subprocess), catch and re-raise with additional context using `raise ... from exc`.
- Prefer context managers (`with`) for short-lived resources; keep long-lived sockets/files as explicit lifecycle-managed objects when appropriate.
- Logging: use existing logging setup; do not add print debugging.
- Logging: record notable lifecycle events and actions with standard Python logging.
- Follow PEP 8 with 120 character line limit
- Use double quotes for Python strings
- Prefer f-strings for string formatting
- Formatting/linting: adhere to repo config (ruff/black/etc.).
- Use dataclasses for data structures when appropriate.
- Use type annotations for all public symbols or where appropriate.
- Each Python file starts with a module docstring describing its purpose.
- Module docstrings must include:
  - SPDX license identifier and copyright line
  - "AS IS / use at own risk" disclaimer
  - High-level module overview (classes/functions and their relationships)
  - Version metadata block (version, date, author, repository)
- Public classes and public functions must have docstrings that explain purpose, usage, parameters,
  return values, and important side effects.  Optimize for the **doc reader** (who sees only the
  rendered docstring, not the signature).  Omit the `Returns` section only when the return value
  is trivially obvious from the function name and type hint (e.g. `is_foo() -> bool`).
- Private classes/functions must have at least a brief docstring (one or two sentences).
- Add brief comments for non-obvious constants, OS-specific terminology, or portability fallbacks.
- For dataclasses, add brief inline comments for non-obvious fields or describe them in the class docstring.
- Use doctests for small, pure functions where examples add clarity; avoid doctests for I/O, timing-dependent behavior, or complex state.


## Security
- Never commit secrets to version control
- Avoid exposing sensitive identifiers (e.g., security hardware IDs, serials, account IDs) in docs, code, tests, or logs.
- Always warn if you notice personal or possibly sensitive information that might be committed (names, emails, device IDs, hostnames, paths, tokens, credentials, internal URLs), and propose safe placeholders before writing or committing.
- Avoid leaking secrets or sensitive identifiers in logs, errors, docs, or tests; redact when needed.
- Treat all external inputs as untrusted; validate/normalize, guard against path traversal, and prefer allowlists.
- When writing files from user input, sanitize filenames and avoid unsafe paths; use `pathlib` and explicit directories.
- For secret/config files, use restrictive permissions (e.g., `0o600`) and avoid world-readable temp files.
- Use secure random number generators (e.g., `secrets` module) and avoid home-grown crypto.
- Favor least-privilege access (filesystem/network/subprocess) and avoid shelling out with untrusted input.
- Data safety policy: never store or commit real financial data (raw outputs, credentials, reports, statements, or API responses)
  in git history. Keep real data strictly outside the repo in ignored locations, and only use sanitized fixtures in `testdata/`.

## Sensitive Data Protection - Jupyter Notebooks
**CRITICAL:** This repository contains notebooks with sensitive data outputs. To prevent leakage
to the public, we have configured nbstripout to remove all output cells from notebooks before committing.
nbstripout does not make sensitive inputs safe to store in notebooks; do not commit real data.
Always ensure that nbstripout is configured correctly before any notebook work:

### Automated Check (run before any notebook work):
```bash
# Check if nbstripout filter is active
if git config --get filter.nbstripout.clean >/dev/null 2>&1; then
    echo "✓ nbstripout is configured"
else
    echo "✗ WARNING: nbstripout NOT configured!"
    echo "Run: uv tool install nbstripout && nbstripout --install"
    exit 1
fi
```

### Setup (if check fails):
```bash
export UV_TOOL_BIN_DIR="$HOME/usr/bin"
uv tool install nbstripout
nbstripout --install
```

**Agent instruction:**
- Run the check before any notebook operations
- If check fails: warn user prominently and offer to run setup
- Never proceed with notebook work if nbstripout is not configured

## Testing
- Add/adjust pytest tests for new behavior.
- At least create one test-script for each feature file in $PROJECT_DIR$/spec
- Name test-scripts according to the feature spec file, e.g. spec/010-foo.md -> tests/test_010_foo.py
- In addition to spec-based tests, add unit tests per module or public function for edge cases and error paths.
- Run relevant tests after changes; if tests fail, fix them before reporting success or explain why they cannot be fixed.
- Always run pytest, mypy, and ruff for relevant changes before reporting success.
- Mock API calls or https: calls in tests
- If a spec implies tests or demo notebooks cannot be added, ask before skipping them.


## Notebooks
- For using functionality interactively we will add demonstration Jupyter notebooks.
- At least create one demo notebook for each feature file in $PROJECT_DIR$/notebooks
- Name notebooks according to the feature spec file, e.g. spec/010-foo.md -> notebooks/demo_010_foo.ipynb
- The first cell in a notebook should be a text cell containing a title as heading and a short description of the feature
- In the second cell, notebooks should activate IPython's autoreload extension and import all relevant modules.
- Notebooks should be divided into code cells that group functionality in a useful manner and order, often code cells will build up on previous ones.
- Notebooks should not mock API calls or https: calls, but use real data.
- If a notebook is impractical or unsafe to add, ask before skipping it.


## Usage
- Add usage documentation to README.md.
- Usage documentation should include information on how to run the code.
- Usage documentation should include a short description of the features


## Output expectations
- If uncertain, propose 2–3 options with tradeoffs.
- Always summarize what changed and why, and list files touched.
