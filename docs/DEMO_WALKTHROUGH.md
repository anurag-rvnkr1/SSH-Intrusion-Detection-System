# Safe end-to-end demo walkthrough

This demonstration writes synthetic records only to a newly created temporary
directory. It does not open an SSH connection and does not target
`/var/log/auth.log` or `/var/log/secure`.

## 1. Prepare an isolated lab

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
LAB_DIR="$(mktemp -d)"
printf 'Lab directory: %s\n' "$LAB_DIR"
```

`mktemp -d` creates a private directory. Keep `$LAB_DIR` in the same shell for
the commands below. The helper creates each config with the test log and JSONL
alert output inside this directory:

```bash
write_demo_config() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys
from pathlib import Path

config_path, log_path, alerts_path = map(Path, sys.argv[1:])
config = {
    "detection": {
        "alert_threshold": 5,
        "window_minutes": 2,
        "cooldown_seconds": 30,
        "future_tolerance_seconds": 60,
    },
    "polling": {
        "interval_seconds": 0.2,
        "initial_read": "beginning",
        "log_files": [str(log_path)],
    },
    "siem": {
        "splunk": {"enabled": False},
        "elk": {"enabled": False},
    },
    "alerts": {"local_file": str(alerts_path)},
}
config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
PY
}
```

## 2. Positive detection and cooldown

Generate two short bursts from one documented TEST-NET source address. The
bursts are two seconds apart, inside the two-minute detection window and the
30-second cooldown:

```bash
write_demo_config "$LAB_DIR/repeat.json" "$LAB_DIR/repeat.log" "$LAB_DIR/repeat-alerts.jsonl"
python3 -m ssh_ids.tests.simulate_attacks \
  --test-mode --log-file "$LAB_DIR/repeat.log" \
  --source-ip 198.51.100.25 --username root \
  --attempts-per-attack 5 --num-attacks 2 \
  --window-seconds 1 --seed 17
```

Expected simulator output is a `TEST MODE: Wrote 10 local simulated records`
message. Verify the records are parseable and chronological:

```bash
python3 - "$LAB_DIR/repeat.log" <<'PY'
import sys
from pathlib import Path
from ssh_ids.src.parser import SSHLogParser

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
events = [SSHLogParser().parse_line(line) for line in lines]
assert len(lines) == 10 and all(event is not None for event in events)
parsed = [event for event in events if event is not None]
assert [event.timestamp for event in parsed] == sorted(event.timestamp for event in parsed)
assert {event.source_ip for event in parsed} == {"198.51.100.25"}
print(f"Verified {len(parsed)} parsed chronological events from {parsed[0].source_ip}")
PY
```

Run the detector for three seconds. GNU `timeout` sends an interrupt, which the
CLI handles as a clean shutdown:

```bash
set -o pipefail
timeout --preserve-status --signal=INT 3s \
  python3 -m ssh_ids.src.main \
  --config "$LAB_DIR/repeat.json" --test-mode --log-file "$LAB_DIR/repeat.log" \
  2>&1 | tee "$LAB_DIR/repeat-output.txt"
```

Expected console behavior: one `SSH IDS alert` JSON record and a shutdown
statistics line showing one alert. The second five-event burst is suppressed
by cooldown; it does not produce a second alert.

Inspect the persisted alert:

```bash
python3 - "$LAB_DIR/repeat-alerts.jsonl" <<'PY'
import json
import sys
from pathlib import Path

alerts = [json.loads(row) for row in Path(sys.argv[1]).read_text().splitlines()]
assert len(alerts) == 1
alert = alerts[0]
for field in ("timestamp", "source_ip", "username", "attempts", "threshold",
              "detection_rule", "attack_type", "severity", "event_details"):
    print(f"{field}: {alert[field]}")
assert alert["source_ip"] == "198.51.100.25"
assert alert["username"] == "root"
assert alert["attempts"] == alert["threshold"] == 5
PY
```

The JSONL alert file survives application restarts. Per-IP attempts, cooldown,
exact-record deduplication, and recent in-memory alert history do not. Replaying
the same log after restarting the detector can therefore create another alert.

## 3. Negative test below threshold

Use a different log and alert file so the result is unambiguous:

```bash
write_demo_config "$LAB_DIR/negative.json" "$LAB_DIR/negative.log" "$LAB_DIR/negative-alerts.jsonl"
python3 -m ssh_ids.tests.simulate_attacks \
  --test-mode --log-file "$LAB_DIR/negative.log" \
  --source-ip 198.51.100.26 --username admin \
  --attempts-per-attack 4 --seed 23
timeout --preserve-status --signal=INT 3s \
  python3 -m ssh_ids.src.main \
  --config "$LAB_DIR/negative.json" --test-mode --log-file "$LAB_DIR/negative.log" \
  >"$LAB_DIR/negative-output.txt" 2>&1
! grep -q 'SSH IDS alert:' "$LAB_DIR/negative-output.txt"
test ! -e "$LAB_DIR/negative-alerts.jsonl"
printf 'Verified: four failures produced no alert at threshold five.\n'
```

The expected result is no alert line and no alert JSONL file, because local
storage is opened only after an alert is generated.

## 4. Safety check and cleanup

Both `--log-file` arguments point inside `$LAB_DIR`, and `--test-mode` rejects
protected authentication-log paths. The simulator independently refuses
protected paths, rotated variants, and symlink-resolved aliases. Do not replace
the temporary paths with production log paths.

After reviewing the files, remove only the directory printed in step 1:

```bash
rm -r -- "$LAB_DIR"
```

If running on an Ubuntu host, optionally compare `stat` output for system logs
before and after the demo. This project does not write those files.
