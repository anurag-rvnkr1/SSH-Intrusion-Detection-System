# Repository Audit

Audit scope: the repository files inventoried on 2026-11-01. The Python IDS is the requested runtime; the repository also contains a Next.js component library. Existing user changes to `tsconfig.json`, `next-env.d.ts`, and `package-lock.json` are outside the audit repairs and must be preserved. Generated `.next/` output is not source and is not included.

## Historical Baseline Findings

The following table records defects discovered before the earlier repair pass;
it is retained as audit history, not as a statement that these defects remain.

| # | Severity | File | Purpose and existing functionality | Problems discovered | Proposed repair | Tests required |
|---|---|---|---|---|---|---|
| 1 | Critical | [ssh_ids/tests/simulate_attacks.py](./ssh_ids/tests/simulate_attacks.py) | Generates SSH-like log records and appends them for demonstrations. | Defaults to `/var/log/auth.log`; fallback can write elsewhere silently; generated timestamps are random/out of order; no protected-path or symlink checks; existing files are appended without clear safety guarantees. | Require safe dedicated default, reject system auth paths after canonicalization, avoid overwrite, deterministic chronological generator, CLI options and explicit print-only operation. | Safe default, protected aliases/symlinks, create/no-overwrite, deterministic records and detector end-to-end tests. |
| 2 | High | [ssh_ids/src/main.py](./ssh_ids/src/main.py), [ssh_ids/src/detector.py](./ssh_ids/src/detector.py), [ssh_ids/src/parser.py](./ssh_ids/src/parser.py), [ssh_ids/src/utils.py](./ssh_ids/src/utils.py), [ssh_ids/tests/test_detector.py](./ssh_ids/tests/test_detector.py) | Main loop, detection, parsing, helpers and unit tests. | `main.py` mutates `sys.path` and imports modules as top-level, while `detector.py` and `parser.py` use relative imports. The existing test discovery fails before tests run (`ImportError: attempted relative import with no known parent package`). Package initializer files are missing. | Establish `ssh_ids` package imports and module entry point; ensure imports have no startup side effects. | Import modules and execute test suite from repository root; CLI `--help` and module launch. |
| 3 | High | [ssh_ids/src/utils.py](./ssh_ids/src/utils.py), [ssh_ids/src/detector.py](./ssh_ids/src/detector.py) | Provides a `RollingWindow` and per-IP alert tracking. | Window cleanup compares historical event times to `datetime.now()`, so replayed/synthetic events are dropped. Naive/aware timestamps can conflict; state is reset at every alert, enabling repeated threshold alerts without cooldown; retained IP state can grow indefinitely. | Use event-time cutoffs with documented `(event_time - window, event_time]` boundary, deterministic out-of-order policy, bounded state cleanup and cooldown. | Exact threshold/window boundaries, historical/out-of-order and timezone tests, repeated alerts/cooldown and cleanup. |
| 4 | High | [ssh_ids/src/detector.py](./ssh_ids/src/detector.py), [ssh_ids/config/config.json](./ssh_ids/config/config.json) | Reads SSH logs and applies configuration thresholds. | Detector hardcodes both OS log paths and ignores `polling.log_files`; it counts any parsed entry as a failure. | Use validated configured paths and only failure-class authentication events; support test log paths and polling configuration. | Multiple/custom paths, missing file, event classification and end-to-end tests. |
| 5 | High | [ssh_ids/src/parser.py](./ssh_ids/src/parser.py), [ssh_ids/tests/sample_auth.log](./ssh_ids/tests/sample_auth.log) | Parses syslog-style SSH messages and sample scenarios. | Accepted logins are not represented; some connection/disconnect messages are treated as authentication failures; source port and PID are not retained; IPv6 validation is incomplete; the parser’s broad exception handling hides defects. Syslog dates use local naive time and the current year. | Parse event type and metadata with standard IP validation, retain raw record, distinguish failures/success/other SSH events, and normalize timestamps consistently. | Realistic IPv4/IPv6 fixtures, all supported event classes, malformed/unknown inputs and timezone/year behavior. |
| 6 | High | [ssh_ids/src/parser.py](./ssh_ids/src/parser.py) | Incrementally reads a configured path and attempts inode-based rotation handling. | Does not detect truncation; inode replacement resets to the new file and can lose unread old-file content; missing files are retried but new file starts from byte zero with no explicit initial-read policy. | Implement explicit offsets, inode/truncation detection, handle lifecycle and configurable initial read behavior; document unavoidable rotation limits. | Append, truncation, replacement, missing file, permission error and multiple-reader tests. |
| 7 | High | [ssh_ids/src/utils.py](./ssh_ids/src/utils.py), [ssh_ids/config/config.json](./ssh_ids/config/config.json) | Loads JSON configuration and validates a small subset of required sections. | Does not validate types/ranges/required nested values, expand `${ENV}` placeholders, or resolve paths relative to a stable location. | Validate config sections and ranges; expand secret environment variables; resolve relative paths from config location; fail clearly for enabled missing credentials. | Valid/missing/invalid config, environment expansion, secrets and relative/multiple paths. |
| 8 | High | [ssh_ids/src/sender.py](./ssh_ids/src/sender.py) | Posts JSON alerts to Splunk HEC and Logstash with retry attempts. | Fixed timeout and retry delay; retries permanent HTTP errors; disabled senders return false, conflating “disabled” with failed delivery; failures are not consistently surfaced; status/payload behavior lacks tests. | Keep TLS verification enabled, configurable timeout and bounded retry for transient failures only; distinguish disabled from failed; ensure local alerts are logged regardless. | Mocked HTTP success, client/server errors, timeout/network failure, retry counts, payload and secret redaction. |
| 9 | Medium | [ssh_ids/src/main.py](./ssh_ids/src/main.py), [ssh_ids/src/detector.py](./ssh_ids/src/detector.py) | Runs polling loop and generates basic alert dictionaries. | CLI only accepts a positional config; no structured alert ID/detection time/attempt detail; unhandled exceptions in processing paths are logged and swallowed; Ctrl+C/shutdown stats have edge cases. | Add argparse CLI, explicit local alert recording and structured deterministic alerts; report actionable errors and exit statuses. | CLI options, signal/shutdown, alert schema and SIEM-disabled behavior. |
| 10 | High | [README.md](./README.md), [install.sh](./install.sh), [run.sh](./run.sh) | Documents installation, monitoring and demonstrations. | README claims production readiness, commands reference nonexistent root `src/` and `config/` paths, encourages root execution, and describes simulator output that does not match configured input. Installer and runner also assume these nonexistent paths and the runner prompts interactively. | Rewrite around verified Python package commands, safe simulator, least privilege and actual config paths; make scripts non-interactive and path-independent or remove misleading operations. | Run documented install/test/module/simulator commands in a clean environment; script path tests. |
| 11 | Medium | [requirements.txt](./requirements.txt), repository root | Declares Python dependency expectations. | Test/lint/type dependencies are only commented out; no pytest configuration, lint/type configuration or CI workflow exists. | Add minimal development requirements and CI for supported Python versions; do not claim unrun CI results. | CI-equivalent local test, coverage, lint and type-check commands. |
| 12 | Medium | [.gitignore](./.gitignore) | Ignores frontend runtime output and local files. | Does not ignore `.env`, Python bytecode/virtualenvs, logs, or generated test data. | Add narrowly scoped Python and secret/local-artifact ignores. | Check ignore rules and ensure no generated credentials/data enter the diff. |
| 13 | Medium | [app/layout.tsx](./app/layout.tsx), [app/globals.css](./app/globals.css), [styles/globals.css](./styles/globals.css), [package.json](./package.json), [next.config.mjs](./next.config.mjs) | Next.js layout, global styles, and UI build configuration. | App metadata remains template text; no `app/page.tsx` exists, so there is no dashboard route. `next.config.mjs` sets `typescript.ignoreBuildErrors: true`. `npm run lint` fails because `eslint` is absent from `node_modules` and the package manifest. The frontend is not integrated with the IDS. | Preserve as a separate incomplete frontend; avoid presenting it as an IDS dashboard. If it is brought into scope, remove ignored type errors, add a real route and lint dependency, and revalidate the lockfile. | `tsc --noEmit` passed; `npm run lint` could not run (`eslint: not found`); frontend build not run. |
| 14 | Low | UI component paths listed in the inventory appendix, [components/theme-provider.tsx](./components/theme-provider.tsx), [hooks/use-mobile.ts](./hooks/use-mobile.ts), [hooks/use-toast.ts](./hooks/use-toast.ts), [lib/utils.ts](./lib/utils.ts), [components.json](./components.json), [postcss.config.mjs](./postcss.config.mjs), [styles/globals.css](./styles/globals.css), static assets under `public/` | Reusable Radix-based UI primitives, hooks, theme helper, styling configuration, and static assets. | No IDS-specific behavior or route consumes these components; `hooks/use-toast.ts` duplicates `components/ui/use-toast.ts`, and `styles/globals.css` duplicates `app/globals.css`. | Preserve generated/reusable frontend assets; remove duplication only when frontend consumers are established. | Frontend type check; focused component tests once used by an actual route. |
| 15 | Low | `package-lock.json`, `next-env.d.ts`, `tsconfig.json` | Frontend dependency lock, generated Next declarations and TypeScript configuration. | `package-lock.json` and `next-env.d.ts` are currently untracked, while `tsconfig.json` has a pre-existing formatting/config change. No Python defect is attributable to these. | Preserve current worktree state; do not rewrite or stage these unrelated files. | Verify final diff does not modify them. |

## Prioritized Repair Plan

1. Make Python package imports consistent and keep module imports side-effect free.
2. Remove the simulator’s unsafe system-log default before adding or running simulator tests.
3. Implement validated configuration, SSH event parsing, event-time detection and safe file monitoring.
4. Record structured alerts locally and repair SIEM transport/retry semantics.
5. Add deterministic tests for each path, plus end-to-end simulation.
6. Correct scripts/docs and add development checks/CI; validate from the repository root.

## Scope Notes

- The inventory contains 92 tracked files. The Python application and test assets are under `ssh_ids/`; the root also contains a separate Next.js frontend and reusable UI primitives.
- A baseline run of `python3 -m unittest discover -s ssh_ids/tests -v` fails while importing `test_detector`; zero tests execute.
- No SIEM endpoints, credentials, or privileged log access are required for local validation.
- This report records findings before repairs. Final validation results will be reported separately and must not be interpreted as a production-readiness certification.

## Remaining File Inventory

The findings above cover the original Python runtime, tests, scripts, README, and major frontend defects. The following tracked paths were also inventoried. Their common frontend assessment is: existing functionality is a reusable generated-style React/Radix primitive or static asset; no IDS-specific logic or consuming route was found; severity Low in this repository's current Python scope; preserve until a dashboard is designed; validate with TypeScript/build and component tests when wired into a route. The local TypeScript check passed, but no build was run and ESLint is unavailable.

| File path | Purpose and observed assessment |
|---|---|
| `components/ui/accordion.tsx` | Accordion primitive wrapper; common frontend assessment above. |
| `components/ui/alert-dialog.tsx` | Alert-dialog primitive wrapper; common frontend assessment above. |
| `components/ui/alert.tsx` | Alert display primitive; common frontend assessment above. |
| `components/ui/aspect-ratio.tsx` | Aspect-ratio primitive wrapper; common frontend assessment above. |
| `components/ui/avatar.tsx` | Avatar primitive wrapper; common frontend assessment above. |
| `components/ui/badge.tsx` | Badge primitive; common frontend assessment above. |
| `components/ui/breadcrumb.tsx` | Breadcrumb navigation primitive; common frontend assessment above. |
| `components/ui/button-group.tsx` | Button-group primitive; common frontend assessment above. |
| `components/ui/button.tsx` | Button primitive; common frontend assessment above. |
| `components/ui/calendar.tsx` | Calendar primitive; common frontend assessment above. |
| `components/ui/card.tsx` | Card layout primitive; common frontend assessment above. |
| `components/ui/carousel.tsx` | Carousel primitive; common frontend assessment above. |
| `components/ui/chart.tsx` | Chart wrappers; common frontend assessment above. |
| `components/ui/checkbox.tsx` | Checkbox primitive; common frontend assessment above. |
| `components/ui/collapsible.tsx` | Collapsible primitive; common frontend assessment above. |
| `components/ui/command.tsx` | Command-menu primitive; common frontend assessment above. |
| `components/ui/context-menu.tsx` | Context-menu primitive; common frontend assessment above. |
| `components/ui/dialog.tsx` | Dialog primitive; common frontend assessment above. |
| `components/ui/drawer.tsx` | Drawer primitive; common frontend assessment above. |
| `components/ui/dropdown-menu.tsx` | Dropdown-menu primitive; common frontend assessment above. |
| `components/ui/empty.tsx` | Empty-state primitive; common frontend assessment above. |
| `components/ui/field.tsx` | Form-field primitives; common frontend assessment above. |
| `components/ui/form.tsx` | Form wrappers; common frontend assessment above. |
| `components/ui/hover-card.tsx` | Hover-card primitive; common frontend assessment above. |
| `components/ui/input-group.tsx` | Input-group primitives; common frontend assessment above. |
| `components/ui/input-otp.tsx` | OTP input primitive; common frontend assessment above. |
| `components/ui/input.tsx` | Input primitive; common frontend assessment above. |
| `components/ui/item.tsx` | Item/list primitives; common frontend assessment above. |
| `components/ui/kbd.tsx` | Keyboard-key display primitive; common frontend assessment above. |
| `components/ui/label.tsx` | Label primitive; common frontend assessment above. |
| `components/ui/menubar.tsx` | Menu-bar primitive; common frontend assessment above. |
| `components/ui/navigation-menu.tsx` | Navigation-menu primitive; common frontend assessment above. |
| `components/ui/pagination.tsx` | Pagination primitive; common frontend assessment above. |
| `components/ui/popover.tsx` | Popover primitive; common frontend assessment above. |
| `components/ui/progress.tsx` | Progress primitive; common frontend assessment above. |
| `components/ui/radio-group.tsx` | Radio-group primitive; common frontend assessment above. |
| `components/ui/resizable.tsx` | Resizable-panel primitive; common frontend assessment above. |
| `components/ui/scroll-area.tsx` | Scroll-area primitive; common frontend assessment above. |
| `components/ui/select.tsx` | Select primitive; common frontend assessment above. |
| `components/ui/separator.tsx` | Separator primitive; common frontend assessment above. |
| `components/ui/sheet.tsx` | Sheet primitive; common frontend assessment above. |
| `components/ui/sidebar.tsx` | Sidebar primitives; common frontend assessment above. |
| `components/ui/skeleton.tsx` | Loading skeleton primitive; common frontend assessment above. |
| `components/ui/slider.tsx` | Slider primitive; common frontend assessment above. |
| `components/ui/sonner.tsx` | Toast library wrapper; common frontend assessment above. |
| `components/ui/spinner.tsx` | Spinner primitive; common frontend assessment above. |
| `components/ui/switch.tsx` | Switch primitive; common frontend assessment above. |
| `components/ui/table.tsx` | Table primitives; common frontend assessment above. |
| `components/ui/tabs.tsx` | Tabs primitive; common frontend assessment above. |
| `components/ui/textarea.tsx` | Textarea primitive; common frontend assessment above. |
| `components/ui/toast.tsx` | Toast primitive; common frontend assessment above. |
| `components/ui/toaster.tsx` | Toast rendering component; common frontend assessment above. |
| `components/ui/toggle-group.tsx` | Toggle-group primitive; common frontend assessment above. |
| `components/ui/toggle.tsx` | Toggle primitive; common frontend assessment above. |
| `components/ui/tooltip.tsx` | Tooltip primitive; common frontend assessment above. |
| `components/ui/use-mobile.tsx` | Responsive breakpoint hook; common frontend assessment above. |
| `components/ui/use-toast.ts` | Toast state hook; duplicate of `hooks/use-toast.ts`. |
| `public/apple-icon.png` | Static Apple touch icon; no IDS behavior. |
| `public/icon-dark-32x32.png` | Static dark-mode icon; no IDS behavior. |
| `public/icon-light-32x32.png` | Static light-mode icon; no IDS behavior. |
| `public/icon.svg` | Static vector icon; no IDS behavior. |
| `public/placeholder-logo.png` | Placeholder image asset; no IDS behavior. |
| `public/placeholder-logo.svg` | Placeholder vector asset; no IDS behavior. |
| `public/placeholder-user.jpg` | Placeholder image asset; no IDS behavior. |
| `public/placeholder.jpg` | Placeholder image asset; no IDS behavior. |
| `public/placeholder.svg` | Placeholder vector asset; no IDS behavior. |
| `components.json` | UI generator aliases and style configuration; no runtime IDS behavior. |
| `postcss.config.mjs` | Tailwind/PostCSS plugin configuration; frontend only. |
| `package.json` | Next.js dependencies and scripts; lint script exists but ESLint is not installed. |
| `package-lock.json` | Untracked local dependency lockfile; preserved without edits. |
| `next-env.d.ts` | Untracked generated Next declaration; preserved without edits. |
| `tsconfig.json` | TypeScript configuration; pre-existing user modification preserved. |
| `ssh_ids/tests/sample_auth.log` | Historical synthetic OpenSSH fixture; retained and now exercised by parser tests. |

## Final Verification Pass

Verification date: 2026-11-01.

### Worktree and preservation

- The branch at the start of this pass was `main`; the repository was already
  dirty. At the start, tracked modifications/deletion were present in
  `.gitignore`, `README.md`, `install.sh`, `requirements.txt`, `run.sh`,
  `ssh_ids/config/config.json`, `ssh_ids/src/{detector,main,parser,sender,utils}.py`,
  `ssh_ids/tests/simulate_attacks.py`, `ssh_ids/tests/test_detector.py`
  (deleted), and `tsconfig.json`.
- At the start, untracked work already included `.env.example`,
  `.github/workflows/ci.yml`, this `AUDIT.md`, `pyproject.toml`,
  `requirements-dev.txt`, package initializers, `alert_store.py`, the focused
  pytest modules, `next-env.d.ts`, and `package-lock.json`. Those existing
  changes were not treated as authored in this pass.
- The pre-existing `tsconfig.json` modification and untracked
  `next-env.d.ts`/`package-lock.json` were not intentionally edited. The
  Next.js build was run and may regenerate `.next/` output, which is ignored.
- No commit, reset, clean, force-push, or destructive Git operation was run.
- No SIEM credential or real authentication log was used.

Changes made in this final verification pass are limited to hardening the
Python implementation/tests, adding Bandit to development checks and CI,
updating the README/audit, and creating the five guides under `docs/`.

### Current Python status and changes in this pass

Confirmed findings and fixes:

1. `NaN`/infinite durations and timeouts passed validation and could later fail
   during time arithmetic or request waits. Numeric configuration now rejects
   non-finite/out-of-range values; retry count and exponential sleep are
   bounded.
2. Replaying an identical raw event within one process could increase the
   failure count. Exact raw-record duplicates are now de-duplicated in bounded
   per-IP state. The de-duplication state is intentionally not persisted.
3. Simulator arguments could request extremely large output or inject
   non-printable host/user values. Generation now has count/window/string
   validation and a 100,000-record cap.
4. Direct sender use could pass a non-HTTP URL to `urllib`; senders now reject
   non-HTTP(S) schemes before opening a URL. Bandit is included in development
   requirements and CI.
5. Backoff growth now has a per-wait ceiling. A file handle is closed if
   `fstat` or the initial seek fails while opening a monitored file.
6. Alerts expose `detection_rule: ssh_failed_authentication_burst`.
7. Configuration bounds aggregate per-poll file reads and total retained
   tracker state. Regression tests cover these limits and restart behavior.

State semantics: the JSONL alert file is append-only and survives process
recreation. Detection attempts, cooldown, exact-record fingerprints, delivery
counters, and the convenience alert-history buffer are in memory only. A
restart with `initial_read: beginning` can replay events and add another alert.

### Reproduced validation

Final local run:

- `python3 -m pytest`: **138 passed**.
- Required core coverage command: **138 passed**, **95.21% aggregate**;
  enforced threshold is 90%.
- `ruff format ssh_ids && ruff check ssh_ids`: passed.
- `mypy ssh_ids/src`: passed.
- `bandit -q -r ssh_ids/src ssh_ids/tests/simulate_attacks.py -ll`: passed.
- `git diff --check`, `bash -n install.sh run.sh`, JSON config parsing, CLI
  `--help`, and `--version`: passed.

The isolated end-to-end run generated ten records from `198.51.100.25` in two
bursts, parsed all ten chronologically, stored one alert because the second
burst was within cooldown, and verified the expected source, username,
threshold, rule, and severity. A separate four-record run generated no alert
at threshold five. Neither `/var/log/auth.log` nor `/var/log/secure` exists in
this workspace, so no host-log metadata comparison was possible. Generated
logs and alerts stayed in a private temporary directory, and protected-path
rejection tests passed. The demo ran in the current Linux workspace, not on an
Ubuntu 24.04 VM.

### SIEM and CI status

Splunk and Logstash payloads, headers, TLS defaults, response handling,
timeouts, retry behavior, disabled integrations, and connection failures are
covered by mocked tests only. No live SIEM integration was attempted.

The GitHub workflow matrix covers Python 3.10–3.14 and now runs pytest with
coverage, Ruff, mypy, and Bandit. It has not been executed on GitHub in this
verification.

### Frontend status

The frontend remains an unintegrated scaffold: there is no IDS page/dashboard
route and no Python API connection. `node_modules/.bin/tsc --noEmit` passed.
`npm run build` compiled and generated only the 404 route; Next.js explicitly
skipped type validation during the build because `next.config.mjs` sets
`typescript.ignoreBuildErrors: true`. `npm run lint` failed because ESLint is
not installed. No dashboard functionality is claimed.

### Remaining operational limitations

- Real authentication-log monitoring was not run; host-specific access must
  be approved and configured read-only by the operator.
- No Ubuntu 24.04 VM, alternate Python matrix runtime, or live SIEM was
  available for this validation.
- The event-time/cooldown/dedup state is not restart-persistent, syslog records
  without year/timezone use host-local assumptions, rotation races remain
  possible, and SIEM delivery is synchronous.

## Final workspace validation follow-up (2026-11-01)

### Prioritized current findings

| Priority | Finding | Status |
|---|---|---|
| Medium | Splunk HEC HTTP 200 responses with a nonzero application `code` were counted as delivered. | Fixed: require bounded valid JSON with integer `code: 0`; added error, malformed-body, oversized-body, and log-redaction tests. |
| Medium | No functional IDS dashboard, API boundary, or backend connection exists in the Next.js scaffold. | Not implemented by design; README now gives a staged, security-conscious future workstream. |
| Low | `npm run lint` is unusable because ESLint is not installed; the Next build produces only `/404`. | Documented; TypeScript check passes, but no frontend lint claim is made. |
| Medium | The repository has no `LICENSE` file. | Not changed; license selection needs maintainer intent. |

### Reproduced final checks

- `python3 -m pytest`: **140 passed** on Python 3.14.2.
- Required coverage run: **140 passed, 95.30% aggregate** (90% minimum).
- Clean temporary venv: dependency installation and `python -m pytest` both
  passed (**140 tests**); `pip check` reported no broken requirements.
- `ruff format --check ssh_ids` and `ruff check ssh_ids`: passed.
- `mypy ssh_ids/src`: passed.
- `bandit -r ssh_ids/src`: passed with no issues.
- CLI help/version, JSON configuration parsing, shell syntax, and
  `git diff --check`: passed.
- Workflow YAML parsed locally; the configured GitHub Actions workflow itself
  was not run remotely.
- Frontend `tsc --noEmit`: passed. `npm run build` compiled but generated only
  `/404` and skipped type validation as configured. `npm run lint` failed
  because `eslint` is unavailable.

### End-to-end and scope evidence

The isolated simulator/detector run parsed ten chronological failures from
`198.51.100.25` and persisted one complete alert across two bursts during
cooldown. A four-failure run produced no console alert or JSONL file. The
alert's source, username, attempt count, threshold, severity, timestamps, and
detection rule were verified. The before/after metadata snapshots for
`/var/log/auth.log` and `/var/log/secure` were identical; both files were
absent in this workspace. The demo used only temporary files and sent no
network traffic.

No live SIEM, Ubuntu 24.04 host, or GitHub Actions run was available. This
validation does not establish production readiness. Persistent state remains
limited to JSONL alerts; detector/cooldown/deduplication state is in memory.

## Repository-wide audit and verification update (2026-11-01)

This update supersedes the earlier test and coverage counts above. The
worktree already contained extensive uncommitted implementation, test, and
documentation changes when this review began; those were inspected and
preserved. During the review the branch advanced to commit
`2c76b8e` (`Add comprehensive tests for SSH brute force detection and log
parsing`); this update did not create that commit. The tracked inventory
contained 115 files by the final verification. Python runtime, tests, fixtures,
configuration, scripts, requirements, CI, Markdown guides, and frontend
source/config/assets were inventoried. No Docker files are present.

### File-level audit

| File path | Purpose and verified functionality | Finding at audit and severity (current status) | Repair or disposition | Validation |
|---|---|---|---|---|
| `ssh_ids/src/main.py` | Canonical argparse CLI; polling loop, local persistence, independent SIEM dispatch, signal shutdown and delivery counters. | No blocking defect found; Low residual risk from synchronous delivery. | Preserve; retain one documented `python -m` entry point. | `test_cli.py`, CLI help/version smoke checks. |
| `ssh_ids/src/detector.py` | Configured readers, per-IP bounded event-time windows, deduplication/cooldown, structured alerts and in-memory recent history. | Tracker/cooldown state is not restart-persistent; Medium limitation. | Document state semantics; persistence remains a future enhancement rather than hidden behavior. | `test_detection.py`, including boundary, out-of-order, cooldown, cleanup, multiple-IP and end-to-end cases. |
| `ssh_ids/src/parser.py` | Bounded incremental reader and OpenSSH parser for authentication, connection and security events; UTC-normalized timestamps and IPv4/IPv6 validation. | Oversized untrusted PID conversion could crash parsing; Medium robustness defect, fixed in this review. | Bound PID conversion and retain otherwise valid records with `process_id=None`. | `test_parser.py` includes an oversized PID regression; `test_file_reader.py` covers file lifecycle. |
| `ssh_ids/src/utils.py` | Config loading/validation, environment expansion, safe-path checks, timestamp/IP utilities and rolling-window helper. | Dashed auth-log rotations were not blocked (High simulator-safety gap) and Splunk token types were unchecked (Medium); both fixed in this review. | Protect dotted/dashed rotations and require non-empty string tokens. | `test_simulator.py` protected-path cases; `test_config.py` invalid token cases. |
| `ssh_ids/src/sender.py` | Splunk HEC and Logstash JSON senders with timeouts, TLS verification, bounded transient retries and status metrics. | Synchronous network retries can delay polling; Medium documented operational limitation. No live SIEM has been tested. | Keep behavior bounded/configurable; use mocked HTTP tests and document that live SIEM delivery remains unverified. | `test_sender.py` mocks payload, response, TLS, timeout and retry behavior. |
| `ssh_ids/src/alert_store.py` | Private, append-only JSONL persistence with path/symlink and ownership/mode checks. | JSONL grows until operator-managed rotation; Low operational limitation. | Document local retention/rotation; do not silently prune alert history. | `test_alert_store.py` checks permissions, append/reopen and path rejection. |
| `ssh_ids/tests/simulate_attacks.py` | Generates local synthetic OpenSSH records; exclusive private-file output and print-only CLI; no network traffic. | Seeded default timestamps changed with calendar year, weakening cross-year determinism; Medium requirement gap, fixed in this review. | Use a fixed UTC epoch when a seed is supplied and no explicit start time is given. | `test_simulator.py` checks stable seeded output, chronology, safe destination and detector compatibility. |
| `ssh_ids/tests/test_config.py` | Configuration, environment, path, bounds, and SIEM validation tests. | No remaining gap identified in reviewed requirements. | Preserve and extend when config behavior changes. | Full pytest suite. |
| `ssh_ids/tests/test_detection.py` | Event-time tracker and detector alert tests, including synthetic-log E2E. | Covers current in-memory semantics; no durable tracker-state behavior is claimed. | Preserve; add persistence tests only with a future persistence design. | Full pytest suite and coverage. |
| `ssh_ids/tests/test_file_reader.py` | Append, partial line, missing file, truncation, rotation, read limit and permission tests. | Filesystem rotation races remain inherently possible. | Keep the limitation explicit; test deterministic rotation behavior. | Full pytest suite. |
| `ssh_ids/tests/test_parser.py` | Classification, metadata, timezones, malformed inputs and fixture coverage. | Oversized PID conversion regression added in this review. | Bound conversion without discarding otherwise valid events. | Full pytest suite. |
| `ssh_ids/tests/test_sender.py` | Mocked HEC/Logstash payload, TLS, response, retry and failure behavior. | No real SIEM is available in this environment. | No credential or network dependency added. | Full pytest suite. |
| `ssh_ids/tests/test_simulator.py` | Safe default, protected aliases, file modes, seed, scenarios and script invocation tests. | Adds dashed auth-log rotation and cross-year deterministic timestamp cases. | Preserve tests as safety gates. | Full pytest suite. |
| `ssh_ids/tests/test_cli.py` | CLI/config selection, test-mode restrictions, alert recording and shutdown behavior. | No real authentication-log monitoring run performed. | Keep all tests filesystem-local. | Full pytest suite and CLI smoke checks. |
| `ssh_ids/tests/test_alert_store.py` | Local alert file persistence and filesystem safety tests. | No disk-quota/retention policy is implemented. | Document operator-managed retention. | Full pytest suite. |
| `ssh_ids/tests/sample_auth.log` | Synthetic SSH sample records used by parser fixture tests. | Not a production log and not a real attack trace. | Preserve as clearly synthetic test data. | `test_parser.py` parses supported and non-failure records. |
| `ssh_ids/config/config.json` | Default detector threshold, polling paths, SIEM toggles and local alert destination. | Default OS log paths vary by distribution and access policy; Low deployment concern. | Document host-specific path selection and least privilege. | JSON parser smoke check; configuration tests use temporary paths. |
| `ssh_ids/__init__.py`, `ssh_ids/src/__init__.py`, `ssh_ids/tests/__init__.py` | Explicit Python package boundaries. | No issue found. | Preserve canonical package imports. | Imports exercised by pytest and module CLI. |
| `install.sh`, `run.sh` | Non-root venv install and cwd-independent module launcher. | Runtime installation does not include developer tooling by design. | Keep development setup separately documented. | `bash -n`; documented module command verified. |
| `requirements.txt`, `requirements-dev.txt`, `pyproject.toml` | Runtime dependency declaration and test/lint/type configuration. | Runtime intentionally has no third-party dependency. | Preserve minimal dependency surface. | Development tools and all configured checks ran locally. |
| `.gitignore`, `.env.example` | Excludes credentials, virtualenv/cache/log artifacts and documents secret variable names without credentials. | `.env` is not auto-loaded; Medium usability constraint. | Document shell/secret-manager setup and never silently load secrets. | Config environment-variable tests; diff/secret review. |
| `.github/workflows/ci.yml` | Python 3.10–3.14 matrix with Ruff, mypy, Bandit and coverage-enforced pytest. | GitHub-hosted workflow has not been run; Low verification limitation. | Verify Actions after push; do not claim remote CI success. | YAML/config reviewed; equivalent current-environment checks run locally. |
| `README.md`, `docs/ARCHITECTURE.md`, `docs/DEMO_WALKTHROUGH.md`, `docs/SIEM_INTEGRATION.md`, `docs/TESTING.md`, `docs/UBUNTU_SETUP.md` | Operator setup, architecture, safe demo, SIEM, tests and limitations. | Must remain aligned with implementation; simulator seed semantics corrected in README during this review. | Keep production readiness explicitly unclaimed and revise docs with behavior changes. | Commands and examples cross-checked against source; CLI/config smoke checks. |
| `app/`, `components/`, `hooks/`, `lib/`, `styles/`, `public/`, `components.json`, `next.config.mjs`, `package.json`, `package-lock.json`, `next-env.d.ts`, `postcss.config.mjs`, `tsconfig.json` | Separate Next.js/React scaffold, reusable UI components, assets and frontend build configuration. | No IDS page/API integration; template metadata remains, build skips TypeScript checks, and ESLint is absent. Medium scope gap; no Python IDS functionality depends on this UI. | Preserve the pre-existing frontend worktree; document it as a scaffold, not a dashboard. | Previously recorded `tsc`/Next checks are not a claim of IDS UI functionality; current task validates Python. |

### Additional fixes in this update

- Protected `/var/log/auth.log-*` rotation names as well as the canonical
  path, dotted rotations, `/var/log/secure` variants, and resolved symlinks.
- Bounded SSH daemon PID parsing so malformed oversized integers cannot crash
  a parser call.
- Made seeded simulator output independent of the current calendar year when
  no explicit start time is passed.
- Rejected enabled Splunk configurations with non-string or whitespace-only
  tokens.

### Latest local validation

- `python3 -m pytest --cov=ssh_ids.src.utils --cov=ssh_ids.src.parser --cov=ssh_ids.src.detector --cov=ssh_ids.src.sender --cov=ssh_ids.src.alert_store --cov=ssh_ids.tests.simulate_attacks --cov-report=term-missing --cov-fail-under=90`: **146 passed**, **95.33% aggregate coverage**.
- `ruff check ssh_ids` and `ruff format --check ssh_ids`: passed.
- `mypy ssh_ids/src`: passed.
- `bandit -q -r ssh_ids/src ssh_ids/tests/simulate_attacks.py -ll`: passed.
- Config JSON validation, CLI help/version, `bash -n install.sh run.sh`, and `git diff --check`: passed.
- Validation ran on Python 3.14.2 only. The Python 3.10–3.14 CI matrix is configured but has not run on GitHub in this review.
- Tests use local temporary files and mocked HTTP; no root, real SIEM credential, or internet access was used. No live Ubuntu VM, real-log access, or SIEM service was available.

The changes do not make this project production-certified. Persistent detection
state, log-rotation race handling, synchronous SIEM dispatch, host-specific
access control, and frontend/dashboard integration remain operational or
future-work limitations.

## Independent final verification (2026-11-01)

At the start of this verification, the branch was `main` at `2c76b8e`, with
pre-existing modifications in `AUDIT.md`, `README.md`, `ssh_ids/src/parser.py`,
`ssh_ids/src/utils.py`, `ssh_ids/tests/simulate_attacks.py`, and three related
test files. The branch subsequently advanced to `418beb0` while these checks
were in progress; this verification did not create that commit or run
commit/reset/checkout operations. The final review added documentation updates
in `AUDIT.md`, `README.md`, and `docs/TESTING.md`; those three files are
modified in the current worktree. `main` is two commits ahead of `origin/main`.
The recorded inventory was 115 tracked files. No frontend files were modified.

### Reproduced automated checks

- `python3 -m pytest`: **146 passed**.
- Required core coverage command with `--cov-fail-under=90`: **146 passed,
  95.33% aggregate coverage**.
- `ruff check ssh_ids`: passed.
- `ruff format --check ssh_ids`: passed.
- `mypy ssh_ids/src`: passed.
- `bandit -q -r ssh_ids/src ssh_ids/tests/simulate_attacks.py -ll`: passed.
- `git diff --check`, configuration JSON parsing, `bash -n install.sh run.sh`,
  CLI help, and CLI version checks: passed.
- Python version for these checks: **3.14.2**. The workflow's Python 3.10–3.14
  matrix and GitHub-hosted CI were not run as part of this verification.

### Isolated CLI end-to-end run

The simulator generated ten chronological local log records from
`198.51.100.25` (two five-record bursts) with seed 17 into a managed temporary
directory. The CLI parsed the file and generated exactly one alert at threshold
5; the second burst fell inside the configured cooldown. Alert JSONL included
timestamp `2024-01-01T00:00:00+00:00`, source IP, username `root`, attempt and
threshold counts, detection rule `ssh_failed_authentication_burst`, severity,
and five event details. A separate four-failure test generated neither an
alert nor an alert file. Replaying the positive log with a newly started
process appended a second alert, confirming alert-file persistence while
detection/cooldown state resets on restart. All temporary files were removed.
The metadata of `/var/log/auth.log` and `/var/log/secure` was unchanged during
the run.

### Frontend and SIEM verification

- `./node_modules/.bin/tsc --noEmit`: passed.
- `npm run build`: compiled successfully, but generated only `/404`; the
  Next.js config skips build-time type validation.
- `npm run lint`: failed because `eslint` is not installed.
- The frontend has no IDS page/dashboard route, no API connection to Python,
  and displays no live detections. It is a UI scaffold only.
- Splunk HEC and Logstash payload, HTTP, retry, and error cases are mocked in
  tests. No live SIEM credentials or endpoints were used.

The final verification used no privileged log access, modified no real
authentication logs, and does not establish operational certification or
production readiness.
