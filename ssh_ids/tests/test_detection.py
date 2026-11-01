from datetime import datetime, timedelta, timezone

from ssh_ids.src.detector import AttackTracker, SSHBruteForceDetector
from ssh_ids.src.parser import LogEntry

NOW = datetime(2024, 1, 1, 0, 10, tzinfo=timezone.utc)
SOURCE = "192.0.2.40"


def make_entry(
    timestamp,
    source_ip=SOURCE,
    username="admin",
    failure_type="failed_password",
    event_type="authentication_failure",
    source_port=None,
    raw_line="",
):
    return LogEntry(
        timestamp=timestamp,
        hostname="test-host",
        service="sshd",
        source_ip=source_ip,
        username=username,
        failure_type=failure_type,
        raw_message="Failed password",
        event_type=event_type,
        source_port=source_port,
        raw_line=raw_line,
    )


def make_tracker(**overrides):
    options = {
        "threshold": 5,
        "window_minutes": 2,
        "cooldown_seconds": 60,
        "future_tolerance_seconds": 0,
        "clock": lambda: NOW,
    }
    options.update(overrides)
    return AttackTracker(**options)


def add_at(tracker, timestamp, ip=SOURCE):
    entry = make_entry(timestamp, ip)
    return tracker.add_failure(ip, timestamp, entry)


def test_threshold_alerts_at_exact_threshold_and_counts_later_events():
    tracker = make_tracker()
    for index in range(4):
        alerted, count = add_at(tracker, NOW - timedelta(seconds=4 - index))
        assert not alerted
        assert count == index + 1
    alerted, count = add_at(tracker, NOW)
    assert alerted and count == 5
    alerted, count = add_at(tracker, NOW)
    assert not alerted and count == 6


def test_attempts_outside_window_and_exact_boundary_are_excluded():
    tracker = make_tracker()
    assert not add_at(tracker, NOW - timedelta(minutes=2))[0]
    assert add_at(tracker, NOW)[1] == 1
    assert tracker.get_attempt_count(SOURCE) == 1


def test_historical_and_timezone_offset_timestamps_work():
    historical = datetime(1999, 1, 1, tzinfo=timezone.utc)
    tracker = make_tracker(clock=lambda: NOW)
    assert add_at(tracker, historical)[1] == 1
    offset_time = (historical + timedelta(seconds=1)).astimezone(timezone(timedelta(hours=5)))
    assert add_at(tracker, offset_time)[1] == 2


def test_out_of_order_events_are_accepted_within_horizon_and_old_events_ignored():
    tracker = make_tracker()
    assert add_at(tracker, NOW)[1] == 1
    assert add_at(tracker, NOW - timedelta(seconds=30))[1] == 1
    assert not add_at(tracker, NOW - timedelta(minutes=2, seconds=1))[0]
    assert tracker.get_attempt_count(SOURCE) == 2


def test_ips_are_independent():
    tracker = make_tracker()
    for index in range(5):
        add_at(tracker, NOW - timedelta(seconds=5 - index), "192.0.2.41")
    assert tracker.get_attempt_count("192.0.2.41") == 5
    assert tracker.get_attempt_count(SOURCE) == 0
    assert add_at(tracker, NOW, SOURCE) == (False, 1)


def test_cooldown_prevents_repeat_alert_then_allows_event_time_realert():
    tracker = make_tracker(cooldown_seconds=30)
    for index in range(5):
        alerted, _ = add_at(tracker, NOW - timedelta(seconds=5 - index))
    assert alerted
    tracker.clock = lambda: NOW + timedelta(seconds=30)
    assert add_at(tracker, NOW + timedelta(seconds=10)) == (False, 6)
    alerted, count = add_at(tracker, NOW + timedelta(seconds=29))
    assert alerted and count == 7


def test_future_naive_and_invalid_timestamps_are_rejected():
    tracker = make_tracker()
    future = NOW + timedelta(seconds=1)
    assert add_at(tracker, future) == (False, 0)
    assert tracker.add_failure(SOURCE, datetime(2024, 1, 1)) == (False, 0)
    assert tracker.get_attempt_count(SOURCE) == 0


def test_invalid_source_ip_is_rejected():
    tracker = make_tracker()
    assert tracker.add_failure("not-an-ip", NOW) == (False, 0)
    assert not tracker.tracked_ips


def test_tracker_bounds_ip_and_per_ip_event_state():
    tracker = make_tracker(threshold=2, max_tracked_ips=2, max_events_per_ip=2)
    for index in range(3):
        add_at(tracker, NOW - timedelta(seconds=3 - index), f"192.0.2.{index + 1}")
    assert len(tracker.tracked_ips) == 2
    ip = "192.0.2.3"
    add_at(tracker, NOW - timedelta(seconds=1), ip)
    add_at(tracker, NOW, ip)
    assert tracker.get_attempt_count(ip) == 2


def test_invalid_user_and_auth_failure_pair_on_same_session_count_once():
    tracker = make_tracker()
    tracker.clock = lambda: NOW + timedelta(seconds=2)
    invalid_user = make_entry(NOW, failure_type="invalid_user", source_port=2222)
    password_failure = make_entry(
        NOW + timedelta(seconds=1), failure_type="failed_password", source_port=2222
    )
    assert tracker.add_failure(SOURCE, NOW, invalid_user) == (False, 1)
    assert tracker.add_failure(SOURCE, password_failure.timestamp, password_failure) == (False, 1)
    assert tracker.get_attempt_count(SOURCE) == 1


def test_exact_duplicate_raw_event_does_not_inflate_attempt_count():
    tracker = make_tracker(threshold=2)
    original = make_entry(
        NOW,
        source_port=2222,
        raw_line="Feb 15 10:10:00 host sshd[1]: same event",
    )
    assert tracker.add_failure(SOURCE, NOW, original) == (False, 1)
    assert tracker.add_failure(SOURCE, NOW, original) == (False, 1)
    distinct = make_entry(
        NOW,
        source_port=2223,
        raw_line="Feb 15 10:10:00 host sshd[2]: distinct event",
    )
    assert tracker.add_failure(SOURCE, NOW, distinct) == (True, 2)


def test_distinct_password_attempts_on_same_session_are_counted():
    tracker = make_tracker()
    tracker.clock = lambda: NOW + timedelta(seconds=2)
    first = make_entry(NOW, source_port=2222)
    second = make_entry(NOW + timedelta(seconds=1), source_port=2222)
    assert tracker.add_failure(SOURCE, first.timestamp, first) == (False, 1)
    assert tracker.add_failure(SOURCE, second.timestamp, second) == (False, 2)


def test_cleanup_removes_stale_ip_state():
    tracker = make_tracker(cooldown_seconds=10, window_minutes=1, max_tracked_ips=1000)
    add_at(tracker, NOW - timedelta(minutes=4), "192.0.2.1")
    for index in range(256):
        source_ip = f"198.51.{index // 254}.{index % 254 + 1}"
        add_at(tracker, NOW - timedelta(minutes=1) + timedelta(seconds=index % 30), source_ip)
    assert "192.0.2.1" not in tracker.tracked_ips


def detector_config(path):
    return {
        "detection": {
            "alert_threshold": 5,
            "window_minutes": 2,
            "cooldown_seconds": 120,
            "future_tolerance_seconds": 0,
        },
        "polling": {
            "interval_seconds": 1,
            "initial_read": "beginning",
            "log_files": [str(path)],
        },
        "siem": {"splunk": {"enabled": False}, "elk": {"enabled": False}},
    }


def test_detector_alert_has_structured_fields_and_local_history(tmp_path):
    detector = SSHBruteForceDetector(
        detector_config(tmp_path / "input.log"),
        clock=lambda: NOW,
        alert_id_factory=lambda: "alert-test",
    )
    try:
        for index in range(5):
            alert = detector._process_entry(
                make_entry(NOW - timedelta(seconds=5 - index)), "/tmp/test.log"
            )
        assert alert is not None
        assert alert["alert_id"] == "alert-test"
        assert alert["attempts"] == alert["threshold"] == 5
        assert alert["detection_rule"] == "ssh_failed_authentication_burst"
        assert alert["source_ip"] == SOURCE
        assert alert["hostname"] == "test-host"
        assert alert["log_source"] == "/tmp/test.log"
        assert len(alert["event_details"]) == 5
        assert detector.get_attack_history() == [alert]
        assert detector.get_attack_history(0) == []
    finally:
        detector.shutdown()


def test_detector_ignores_success_events_and_emits_only_failed_attempts(tmp_path):
    detector = SSHBruteForceDetector(detector_config(tmp_path / "input.log"), clock=lambda: NOW)
    success = make_entry(NOW, event_type="authentication_success")
    assert detector._process_entry(success) is None
    detector.shutdown()


def test_detector_bounds_retained_alert_history(tmp_path):
    config = detector_config(tmp_path / "input.log")
    config["detection"]["max_alert_history"] = 2
    detector = SSHBruteForceDetector(config, clock=lambda: NOW)
    try:
        for last_octet in range(1, 4):
            source_ip = f"192.0.2.{last_octet}"
            for index in range(5):
                entry = make_entry(
                    NOW - timedelta(seconds=5 - index),
                    source_ip=source_ip,
                )
                detector._process_entry(entry)
        history = detector.get_attack_history()
        assert len(history) == 2
        assert [alert["source_ip"] for alert in history] == ["192.0.2.2", "192.0.2.3"]
    finally:
        detector.shutdown()


def test_detector_uses_configured_log_files_and_generates_end_to_end_alerts(tmp_path):
    from ssh_ids.tests.simulate_attacks import AttackSimulator

    log_path = tmp_path / "simulation.log"
    start = NOW - timedelta(seconds=10)
    simulator = AttackSimulator(log_path, seed=13, start_time=start)
    count = simulator.write_attacks_to_file(
        attempts_per_attack=5,
        source_ips=[SOURCE],
        usernames=["root"],
    )
    assert count == 5
    detector = SSHBruteForceDetector(
        detector_config(log_path), clock=lambda: NOW, alert_id_factory=lambda: "e2e-id"
    )
    try:
        alerts = detector.process_logs()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "e2e-id"
        assert alerts[0]["attempts"] == 5
        assert alerts[0]["source_ip"] == SOURCE
        assert detector.process_logs() == []
    finally:
        detector.shutdown()


def test_detection_state_resets_after_restart_and_replay_can_alert_again(tmp_path):
    from ssh_ids.tests.simulate_attacks import AttackSimulator

    log_path = tmp_path / "replay.log"
    AttackSimulator(
        log_path, seed=13, start_time=NOW - timedelta(seconds=10)
    ).write_attacks_to_file(attempts_per_attack=5, source_ips=[SOURCE], usernames=["root"])
    first = SSHBruteForceDetector(detector_config(log_path), clock=lambda: NOW)
    try:
        assert len(first.process_logs()) == 1
    finally:
        first.shutdown()

    restarted = SSHBruteForceDetector(detector_config(log_path), clock=lambda: NOW)
    try:
        assert len(restarted.process_logs()) == 1
    finally:
        restarted.shutdown()


def test_detector_processes_multiple_configured_files(tmp_path):
    from ssh_ids.tests.simulate_attacks import AttackSimulator

    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first_entries = AttackSimulator(first, seed=2, start_time=NOW - timedelta(seconds=10))
    first.write_text(
        "\n".join(
            first_entries.generate_entries(
                attempts_per_attack=3, source_ips=[SOURCE], usernames=["root"]
            )
        )
        + "\n",
        encoding="utf-8",
    )
    second_entries = AttackSimulator(second, seed=4, start_time=NOW - timedelta(seconds=7))
    second.write_text(
        "\n".join(
            second_entries.generate_entries(
                attempts_per_attack=2, source_ips=[SOURCE], usernames=["root"]
            )
        )
        + "\n",
        encoding="utf-8",
    )
    config = detector_config(first)
    config["polling"]["log_files"] = [str(first), str(second)]
    detector = SSHBruteForceDetector(config, clock=lambda: NOW)
    try:
        alerts = detector.process_logs()
        assert len(alerts) == 1
        assert alerts[0]["attempts"] == 5
    finally:
        detector.shutdown()
