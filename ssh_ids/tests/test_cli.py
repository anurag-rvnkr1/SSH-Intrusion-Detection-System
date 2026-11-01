import json
from pathlib import Path

import pytest

from ssh_ids.src.main import SSHIDSApplication, main


def config_file(path, log_files):
    config = {
        "detection": {"alert_threshold": 5, "window_minutes": 2},
        "polling": {
            "interval_seconds": 0.1,
            "initial_read": "end",
            "log_files": [str(item) for item in log_files],
        },
        "siem": {"splunk": {"enabled": False}, "elk": {"enabled": False}},
        "alerts": {"local_file": str(path.parent / "alerts.jsonl")},
    }
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_application_accepts_test_logs_and_overrides_initial_read(tmp_path):
    log_path = tmp_path / "fixture.log"
    config = config_file(tmp_path / "config.json", [log_path])
    app = SSHIDSApplication(config, test_mode=True)
    try:
        assert app.config["polling"]["log_files"] == [str(log_path)]
        assert app.config["polling"]["initial_read"] == "beginning"
        assert app.test_mode
    finally:
        app.shutdown()


def test_verbose_enables_child_module_debug_logs(tmp_path):
    import logging

    config = config_file(tmp_path / "config.json", [tmp_path / "fixture.log"])
    app = SSHIDSApplication(config, verbose=True)
    try:
        assert logging.getLogger("ssh_ids.src.parser").getEffectiveLevel() == logging.DEBUG
    finally:
        app.shutdown()


def test_test_mode_refuses_system_authentication_paths(tmp_path):
    config = config_file(tmp_path / "config.json", [Path("/var/log/auth.log")])
    with pytest.raises(ValueError, match="dedicated test log"):
        SSHIDSApplication(config, test_mode=True)


def test_log_file_option_overrides_configured_paths(tmp_path):
    config = config_file(tmp_path / "config.json", [tmp_path / "first.log"])
    selected = tmp_path / "selected.log"
    app = SSHIDSApplication(config, log_file=selected)
    try:
        assert app.config["polling"]["log_files"] == [str(selected)]
    finally:
        app.shutdown()


def test_alert_is_persisted_and_logged_when_siem_is_disabled(tmp_path, caplog):
    config = config_file(tmp_path / "config.json", [tmp_path / "log"])
    app = SSHIDSApplication(config)
    try:
        app._log_alert({"alert_id": "local-id", "source_ip": "192.0.2.1"})
        assert "local-id" in caplog.text
        assert '"alert_id":"local-id"' in (tmp_path / "alerts.jsonl").read_text(encoding="utf-8")
        assert app.siem.send_alert({"alert_id": "local-id"}) is None
        assert app.stats["failed_sends"] == 0
    finally:
        app.shutdown()


def test_application_run_starts_polls_and_shuts_down_cleanly(tmp_path, monkeypatch):
    config = config_file(tmp_path / "config.json", [tmp_path / "fixture.log"])
    app = SSHIDSApplication(config)
    batches = iter([[{"alert_id": "run-alert", "source_ip": "192.0.2.2"}], []])
    monkeypatch.setattr(app.detector, "process_logs", lambda: next(batches))
    monkeypatch.setattr(app._stop, "wait", lambda _timeout: app._stop.set())
    assert app.run() == 0
    assert app.stats["processed_alerts"] == 1
    assert app.stats["failed_sends"] == 0
    assert '"alert_id":"run-alert"' in (tmp_path / "alerts.jsonl").read_text(encoding="utf-8")


def test_application_handles_keyboard_interrupt(tmp_path, monkeypatch):
    config = config_file(tmp_path / "config.json", [tmp_path / "fixture.log"])
    app = SSHIDSApplication(config)
    monkeypatch.setattr(app.detector, "process_logs", lambda: [])
    monkeypatch.setattr(
        app._stop, "wait", lambda _timeout: (_ for _ in ()).throw(KeyboardInterrupt)
    )
    assert app.run() == 0


def test_cli_help_version_and_missing_config(capsys):
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    assert "--test-mode" in capsys.readouterr().out
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0
    assert main(["--config", "/missing/ssh-ids.json"]) == 2
    assert "Configuration file not found" in capsys.readouterr().err


def test_cli_rejects_unknown_arguments(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--not-a-supported-option"])
    assert exit_info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
