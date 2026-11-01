import json
import math

import pytest

from ssh_ids.src.utils import (
    RollingWindow,
    calculate_attack_window,
    format_alert_timestamp,
    get_hostname,
    is_valid_ip,
    load_config,
    sanitize_log_entry,
    setup_logger,
    validate_config,
)


def valid_config(log_files=None):
    return {
        "detection": {"alert_threshold": 5, "window_minutes": 2},
        "polling": {
            "interval_seconds": 1,
            "initial_read": "beginning",
            "log_files": log_files or ["fixture.log"],
        },
        "siem": {"splunk": {"enabled": False}, "elk": {"enabled": False}},
    }


def test_config_resolves_multiple_relative_paths(tmp_path):
    config = validate_config(valid_config(["one.log", "nested/two.log"]), tmp_path)
    assert config["polling"]["log_files"] == [
        str(tmp_path / "one.log"),
        str(tmp_path / "nested/two.log"),
    ]


def test_config_rejects_excessive_number_of_log_paths(tmp_path):
    with pytest.raises(ValueError, match="more than 64"):
        validate_config(valid_config([f"{index}.log" for index in range(65)]), tmp_path)


def test_config_rejects_state_and_read_limits_that_exceed_global_bounds(tmp_path):
    config = valid_config()
    config["detection"].update({"max_tracked_ips": 4096, "max_events_per_ip": 256})
    with pytest.raises(ValueError, match="global state limit"):
        validate_config(config, tmp_path)

    config = valid_config([f"{index}.log" for index in range(5)])
    config["polling"]["max_bytes_per_poll"] = 16 * 1024 * 1024
    with pytest.raises(ValueError, match="64 MiB"):
        validate_config(config, tmp_path)


def test_config_loads_and_expands_environment_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "test-token")
    config = valid_config()
    config["siem"]["splunk"] = {
        "enabled": True,
        "url": "https://splunk.example:8088",
        "token": "${SPLUNK_HEC_TOKEN}",
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    loaded = load_config(path)
    assert loaded["siem"]["splunk"]["token"] == "test-token"
    assert loaded["polling"]["log_files"] == [str(tmp_path / "fixture.log")]


def test_missing_secret_fails_without_exposing_its_value(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVATE_HEC_TOKEN", raising=False)
    config = valid_config()
    config["siem"]["splunk"] = {
        "enabled": True,
        "url": "https://splunk.example",
        "token": "${PRIVATE_HEC_TOKEN}",
    }
    with pytest.raises(ValueError, match="PRIVATE_HEC_TOKEN"):
        validate_config(config, tmp_path)


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        ("detection", "alert_threshold", 0, "positive integer"),
        ("detection", "max_alert_history", 0, "between 1 and 10000"),
        ("detection", "max_alert_history", 10001, "between 1 and 10000"),
        ("detection", "max_tracked_ips", 65537, "between 1 and 65536"),
        ("detection", "max_events_per_ip", 4097, "between 1 and 4096"),
        ("detection", "window_minutes", -1, "between 0 and 10080"),
        ("detection", "cooldown_seconds", -1, "between 0 and 2592000"),
        ("polling", "interval_seconds", 0, "between 0 and 3600"),
        ("polling", "log_files", [], "non-empty list"),
        ("polling", "initial_read", "middle", "initial_read"),
        ("polling", "max_bytes_per_poll", 0, "between 1"),
    ],
)
def test_invalid_config_values_are_rejected(section, key, value, message, tmp_path):
    config = valid_config()
    config[section][key] = value
    with pytest.raises(ValueError, match=message):
        validate_config(config, tmp_path)


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        ("detection", "window_minutes", math.nan, "between 0 and 10080"),
        ("detection", "cooldown_seconds", math.inf, "between 0 and 2592000"),
        ("polling", "interval_seconds", math.nan, "between 0 and 3600"),
    ],
)
def test_non_finite_detection_and_polling_values_are_rejected(
    section, key, value, message, tmp_path
):
    config = valid_config()
    config[section][key] = value
    with pytest.raises(ValueError, match=message):
        validate_config(config, tmp_path)


@pytest.mark.parametrize("section", ["detection", "polling", "siem"])
def test_missing_required_sections_are_rejected(section, tmp_path):
    config = valid_config()
    del config[section]
    with pytest.raises(ValueError, match=section):
        validate_config(config, tmp_path)


def test_enabled_destination_requires_valid_url_and_secret(tmp_path):
    config = valid_config()
    config["siem"]["splunk"] = {"enabled": True, "url": "file:///tmp/x", "token": "token"}
    with pytest.raises(ValueError, match="http or https"):
        validate_config(config, tmp_path)
    config["siem"]["splunk"] = {"enabled": True, "url": "https://splunk.example"}
    with pytest.raises(ValueError, match="token is required"):
        validate_config(config, tmp_path)


@pytest.mark.parametrize("token", [1, [], {}, "  "])
def test_enabled_splunk_requires_nonempty_string_token(token, tmp_path):
    config = valid_config()
    config["siem"]["splunk"] = {
        "enabled": True,
        "url": "https://splunk.example",
        "token": token,
    }
    with pytest.raises(ValueError, match="token is required as a non-empty string"):
        validate_config(config, tmp_path)


def test_disabled_destination_does_not_require_endpoint_or_secret(tmp_path):
    result = validate_config(valid_config(), tmp_path)
    assert result["siem"]["splunk"]["enabled"] is False
    assert result["siem"]["elk"]["enabled"] is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timeout_seconds", 0, "timeout_seconds"),
        ("max_attempts", 0, "max_attempts"),
        ("retry_backoff_seconds", -1, "retry_backoff_seconds"),
        ("ssl_verify", "false", "ssl_verify"),
    ],
)
def test_invalid_siem_delivery_options_are_rejected(field, value, message, tmp_path):
    config = valid_config()
    config["siem"]["elk"] = {"enabled": False, field: value}
    with pytest.raises(ValueError, match=message):
        validate_config(config, tmp_path)


def test_siem_retry_attempts_are_bounded(tmp_path):
    config = valid_config()
    config["siem"]["elk"] = {"enabled": False, "max_attempts": 11}
    with pytest.raises(ValueError, match="between 1 and 10"):
        validate_config(config, tmp_path)


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_non_finite_siem_timeout_and_backoff_are_rejected(value, tmp_path):
    for field in ("timeout_seconds", "retry_backoff_seconds"):
        config = valid_config()
        config["siem"]["elk"] = {"enabled": False, field: value}
        with pytest.raises(ValueError, match=field):
            validate_config(config, tmp_path)


def test_enabled_elastic_headers_and_boolean_flags_are_validated(tmp_path):
    config = valid_config()
    config["siem"]["elk"] = {
        "enabled": True,
        "url": "http://logstash.example",
        "headers": {"X-Api-Key": 4},
    }
    with pytest.raises(ValueError, match="headers"):
        validate_config(config, tmp_path)
    config["siem"]["elk"] = {"enabled": "true", "url": "http://logstash.example"}
    with pytest.raises(ValueError, match="enabled must be a boolean"):
        validate_config(config, tmp_path)


def test_local_alert_path_must_not_be_a_system_auth_log(tmp_path):
    config = valid_config()
    config["alerts"] = {"local_file": "/var/log/auth.log"}
    with pytest.raises(ValueError, match="system authentication log"):
        validate_config(config, tmp_path)


def test_load_config_reports_missing_and_malformed_files(tmp_path):
    with pytest.raises(FileNotFoundError, match="Configuration file not found"):
        load_config(tmp_path / "absent.json")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_config(invalid)
    invalid.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be a JSON object"):
        load_config(invalid)


def test_ip_validation_uses_standard_ipv4_and_ipv6_parsing():
    assert is_valid_ip("192.0.2.1")
    assert is_valid_ip("2001:db8::1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("256.0.2.1")
    assert not is_valid_ip("1234::xyz")
    assert not is_valid_ip("")
    assert not is_valid_ip(None)


def test_log_sanitizer_removes_controls_and_bounds_input():
    assert sanitize_log_entry("ssh\x00d\x01") == "sshd"
    assert len(sanitize_log_entry("x" * 9000)) == 8192


def test_rolling_window_is_event_time_sorted_and_excludes_exact_lower_boundary():
    from datetime import datetime, timedelta, timezone

    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    window = RollingWindow(2)
    assert window.add(start)
    assert window.add(start + timedelta(minutes=2))
    assert window.count(start + timedelta(minutes=2)) == 1
    assert window.events == [start + timedelta(minutes=2)]
    assert not window.add(start - timedelta(seconds=1))
    window.reset()
    assert window.count() == 0


def test_rolling_window_normalizes_timezone_offsets():
    from datetime import datetime, timedelta, timezone

    utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    offset = timezone(timedelta(hours=2))
    window = RollingWindow(2)
    window.add(utc)
    window.add(utc.astimezone(offset))
    assert window.count() == 2


def test_rolling_window_rejects_bad_duration_and_naive_time():
    from datetime import datetime

    with pytest.raises(ValueError, match="window_minutes"):
        RollingWindow(0)
    with pytest.raises(ValueError, match="window_minutes"):
        RollingWindow(math.nan)
    with pytest.raises(ValueError, match="timezone-aware"):
        RollingWindow().add(datetime(2024, 1, 1))


def test_timestamp_utilities_are_utc_and_hostname_has_fallback():
    from datetime import datetime, timedelta, timezone
    from unittest.mock import patch

    event_time = datetime(2024, 1, 1, 2, tzinfo=timezone(timedelta(hours=2)))
    assert calculate_attack_window(event_time, 1) == datetime(
        2024, 1, 1, 0, 0, tzinfo=timezone.utc
    ) - timedelta(minutes=1)
    assert format_alert_timestamp(event_time) == "2024-01-01T00:00:00+00:00"
    with patch("ssh_ids.src.utils.socket.gethostname", side_effect=OSError):
        assert get_hostname() == "unknown-host"


def test_logger_rejects_invalid_level():
    with pytest.raises(ValueError, match="Invalid log level"):
        setup_logger("ssh-ids-test-invalid-level", "NOT_A_LEVEL")
