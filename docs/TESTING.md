# Testing and validation

## Local commands

Run from the repository root with `requirements-dev.txt` installed:

```bash
python3 -m pytest
python3 -m pytest ssh_ids/tests/test_detection.py -v
python3 -m pytest \
  --cov=ssh_ids.src.utils \
  --cov=ssh_ids.src.parser \
  --cov=ssh_ids.src.detector \
  --cov=ssh_ids.src.sender \
  --cov=ssh_ids.src.alert_store \
  --cov=ssh_ids.tests.simulate_attacks \
  --cov-report=term-missing \
  --cov-fail-under=90
ruff check ssh_ids
mypy ssh_ids/src
bandit -q -r ssh_ids/src ssh_ids/tests/simulate_attacks.py -ll
git diff --check
```

The tests use temporary directories, deterministic timestamps, and mocked HTTP
responses. They do not need root, live SIEM credentials, or a network
connection. Simulator tests reject system authentication logs and symlink
aliases rather than writing to them.

## Covered behaviors

The suite covers threshold and window boundaries, historical and out-of-order
events, multiple IPs, event deduplication, cooldown, timestamp normalization,
parser classifications, file append/truncation/rotation/missing paths,
configuration and secret expansion, simulator path safety, private JSONL
storage/recreation, CLI behavior, mocked SIEM success/failure/retries, and an
end-to-end synthetic-log detection flow. Splunk HEC tests validate its JSON
response code, including HTTP 200 responses with nonzero HEC error codes and
malformed or oversized response bodies.

Alert-file persistence is verified independently from tracker state. A new
`LocalAlertStore` instance appends without deleting earlier rows; a new
detector has fresh in-memory cooldown and deduplication state. Replaying a log
after restart may therefore generate a new alert.

## CLI and configuration smoke checks

```bash
python3 -m json.tool ssh_ids/config/config.json >/dev/null
python3 -m ssh_ids.src.main --help
python3 -m ssh_ids.src.main --version
bash -n install.sh run.sh
```

Do not run the default configuration against real authentication logs as a test.
Use `--test-mode --log-file PATH` with a dedicated temporary file.

## CI

The GitHub Actions workflow installs development requirements and runs Ruff,
mypy, Bandit security lint, and the complete coverage-enforced pytest suite
for Python 3.10 through 3.14. A workflow file being present is not evidence
that a GitHub-hosted run passed; check the Actions page after pushing.

## Frontend checks

The frontend is separate from the IDS. `./node_modules/.bin/tsc --noEmit` is a direct
TypeScript check. The checked-in Next.js config skips type validation during
`next build`, so run the TypeScript command separately. The `npm run lint`
script requires ESLint, which is not listed in the frontend dev dependencies
in the inspected worktree.
