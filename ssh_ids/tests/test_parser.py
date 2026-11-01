from datetime import datetime, timezone

import pytest

from ssh_ids.src.parser import SSHLogParser

PARSER = SSHLogParser()


def line(message, timestamp="Feb 15 10:15:23", hostname="ubuntu", pid=1234):
    return f"{timestamp} {hostname} sshd[{pid}]: {message}"


@pytest.mark.parametrize(
    ("message", "failure_type", "username", "ip", "port"),
    [
        ("Invalid user admin from 192.0.2.10", "invalid_user", "admin", "192.0.2.10", None),
        (
            "Failed password for root from 192.0.2.11 port 54321 ssh2",
            "failed_password",
            "root",
            "192.0.2.11",
            54321,
        ),
        (
            "Failed password for invalid user test from 192.0.2.12 port 22 ssh2",
            "failed_password",
            "test",
            "192.0.2.12",
            22,
        ),
        (
            "Failed publickey for alice from 2001:db8::1 port 2200 ssh2",
            "failed_publickey",
            "alice",
            "2001:db8::1",
            2200,
        ),
        (
            "Failed keyboard-interactive/pam for bob from ::1 port 22 ssh2",
            "failed_authentication",
            "bob",
            "::1",
            22,
        ),
    ],
)
def test_classifies_authentication_failures(message, failure_type, username, ip, port):
    entry = PARSER.parse_line(line(message), current_year=2024)
    assert entry is not None
    assert entry.event_type == "authentication_failure"
    assert entry.failure_type == failure_type
    assert entry.username == username
    assert entry.source_ip == ip
    assert entry.source_port == port
    assert entry.process_id == 1234
    assert entry.hostname == "ubuntu"
    assert entry.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    ("message", "failure_type", "username"),
    [
        ("Accepted password for admin from 192.0.2.20 port 22 ssh2", "accepted_password", "admin"),
        (
            "Accepted publickey for deploy from 2001:db8::2 port 22 ssh2",
            "accepted_publickey",
            "deploy",
        ),
        (
            "Accepted keyboard-interactive/pam for operator from 192.0.2.21 port 22 ssh2",
            "accepted_authentication",
            "operator",
        ),
    ],
)
def test_successful_authentication_is_not_a_failure(message, failure_type, username):
    entry = PARSER.parse_line(line(message), current_year=2024)
    assert entry is not None
    assert entry.event_type == "authentication_success"
    assert not entry.is_failure
    assert entry.failure_type == failure_type
    assert entry.username == username


@pytest.mark.parametrize(
    ("message", "failure_type", "event_type", "ip"),
    [
        (
            "Connection closed by invalid user guest 192.0.2.22 port 22 [preauth]",
            "connection_closed",
            "connection",
            "192.0.2.22",
        ),
        (
            "Disconnected from 192.0.2.23 port 22 [preauth]",
            "disconnected",
            "connection",
            "192.0.2.23",
        ),
        (
            "Received disconnect from 2001:db8::3 port 22 [preauth]",
            "disconnected",
            "connection",
            "2001:db8::3",
        ),
        (
            "Timeout before authentication for 192.0.2.24 port 22",
            "authentication_timeout",
            "connection",
            "192.0.2.24",
        ),
        ("Connection reset by ::1 [preauth]", "connection_reset", "connection", "::1"),
        (
            "Connection from 192.0.2.25 port 5555 on 192.0.2.1 port 22",
            "connection_received",
            "connection",
            "192.0.2.25",
        ),
        (
            'Bad protocol version identification "SSH-2.0-INVALID" from 192.0.2.26 port 22',
            "invalid_protocol",
            "security_event",
            "192.0.2.26",
        ),
        (
            "Unable to negotiate with 192.0.2.27 port 22: no matching cipher found",
            "negotiation_failure",
            "security_event",
            "192.0.2.27",
        ),
        (
            "maximum authentication attempts exceeded for user root from 192.0.2.28 port 22",
            "authentication_limit",
            "security_event",
            "192.0.2.28",
        ),
    ],
)
def test_classifies_other_ssh_events_without_counting_them_as_failures(
    message, failure_type, event_type, ip
):
    entry = PARSER.parse_line(line(message), current_year=2024)
    assert entry is not None
    assert entry.failure_type == failure_type
    assert entry.event_type == event_type
    assert entry.source_ip == ip
    assert not entry.is_failure


def test_parses_iso_timestamps_and_normalizes_to_utc():
    entry = PARSER.parse_line(
        line("Failed password for admin from 192.0.2.30 port 22", "2024-02-15T12:15:23+02:00")
    )
    assert entry is not None
    assert entry.timestamp == datetime(2024, 2, 15, 10, 15, 23, tzinfo=timezone.utc)


def test_invalid_or_unknown_lines_are_ignored_safely():
    assert PARSER.parse_line("") is None
    assert PARSER.parse_line("not a syslog record") is None
    assert PARSER.parse_line(line("Failed password for root from 999.0.0.1 port 22")) is None
    assert PARSER.parse_line(line("Feb 31 10:15:23", timestamp="Feb 31 10:15:23")) is None
    assert PARSER.parse_line(line("pam_unix(sshd:session): session opened for user root")) is None


def test_preserves_sanitized_original_record():
    entry = PARSER.parse_line(line("Failed password for admin from 192.0.2.31 port 22\x00"))
    assert entry is not None
    assert "\x00" not in entry.raw_line
    assert entry.to_dict()["source_ip"] == "192.0.2.31"


def test_direct_parser_input_is_bounded_before_pattern_matching():
    entry = PARSER.parse_line(
        line("Failed password for admin from 192.0.2.31 port 22") + ("x" * 1_000_000)
    )
    assert entry is not None
    assert len(entry.raw_line) <= 8192


def test_timezone_naive_iso_timestamp_is_assigned_local_timezone():
    entry = PARSER.parse_line(
        line("Failed password for root from 192.0.2.32", "2024-02-15T10:15:23")
    )
    assert entry is not None
    assert entry.timestamp.tzinfo is not None


def test_sample_auth_fixture_contains_supported_and_nonfailure_events():
    from pathlib import Path

    fixture = Path(__file__).with_name("sample_auth.log")
    entries = [
        PARSER.parse_line(item, current_year=2024)
        for item in fixture.read_text(encoding="utf-8").splitlines()
    ]
    parsed = [entry for entry in entries if entry is not None]
    assert len(parsed) >= 30
    assert any(entry.event_type == "authentication_success" for entry in parsed)
    assert any(entry.event_type == "security_event" for entry in parsed)
    assert any(entry.event_type == "connection" for entry in parsed)
