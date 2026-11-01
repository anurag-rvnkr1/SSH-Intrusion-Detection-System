"""OpenSSH authentication event parsing and incremental log-file reading."""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Literal

from .utils import normalize_timestamp, sanitize_log_entry

logger = logging.getLogger(__name__)
_MAX_RECORD_BYTES = 8192
EventType = Literal[
    "authentication_failure",
    "authentication_success",
    "connection",
    "security_event",
]

_HEADER = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|"
    r"(?:\d{4}-\d{2}-\d{2}[T ]\S+))\s+"
    r"(?P<hostname>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_IP_CANDIDATE = re.compile(
    r"(?<![\w])(\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F:]*)"
)
_PORT = re.compile(r"\bport\s+(\d{1,5})\b")
_FAILURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "failed_password",
        re.compile(r"Failed password for (?:invalid user )?(?P<username>\S+) from ", re.I),
    ),
    (
        "failed_publickey",
        re.compile(r"Failed publickey for (?:invalid user )?(?P<username>\S+) from ", re.I),
    ),
    (
        "failed_authentication",
        re.compile(
            r"Failed (?:keyboard-interactive(?:/pam)?|none|hostbased) for "
            r"(?:invalid user )?(?P<username>\S+) from ",
            re.I,
        ),
    ),
    ("invalid_user", re.compile(r"Invalid user (?P<username>\S+) from ", re.I)),
)
_SUCCESSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("accepted_password", re.compile(r"Accepted password for (?P<username>\S+) from ", re.I)),
    ("accepted_publickey", re.compile(r"Accepted publickey for (?P<username>\S+) from ", re.I)),
    (
        "accepted_authentication",
        re.compile(
            r"Accepted (?:keyboard-interactive(?:/pam)?|hostbased) for (?P<username>\S+) from ",
            re.I,
        ),
    ),
)
_CONNECTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("connection_closed", re.compile(r"Connection closed by ", re.I)),
    ("disconnected", re.compile(r"(?:Disconnected from|Received disconnect from) ", re.I)),
    (
        "authentication_timeout",
        re.compile(
            r"(?:Timeout before authentication|Connection timed out|timed out "
            r"waiting for input)",
            re.I,
        ),
    ),
    ("connection_reset", re.compile(r"Connection reset by ", re.I)),
    ("connection_received", re.compile(r"Connection from ", re.I)),
)
_SECURITY_EVENTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "invalid_protocol",
        re.compile(
            r"(?:Bad protocol version identification.*?from |"
            r"Did not receive identification string.*?from )",
            re.I,
        ),
    ),
    (
        "negotiation_failure",
        re.compile(
            r"(?:Unable to negotiate with|no matching (?:cipher|MAC|key exchange method))", re.I
        ),
    ),
    ("authentication_limit", re.compile(r"maximum authentication attempts exceeded", re.I)),
)


@dataclass(frozen=True)
class LogEntry:
    """A recognized SSH log record with normalized metadata."""

    timestamp: datetime
    hostname: str
    service: str
    source_ip: str | None
    username: str | None
    failure_type: str
    raw_message: str
    event_type: EventType = "authentication_failure"
    source_port: int | None = None
    process_id: int | None = None
    raw_line: str = ""

    @property
    def is_failure(self) -> bool:
        """Whether this event represents a failed authentication attempt."""
        return self.event_type == "authentication_failure"

    def to_dict(self) -> dict[str, object]:
        """Return safe structured metadata for logs and downstream consumers."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "service": self.service,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "username": self.username,
            "event_type": self.event_type,
            "failure_type": self.failure_type,
            "process_id": self.process_id,
        }


class SSHLogParser:
    """Parse common syslog and ISO-timestamped OpenSSH records."""

    def parse_line(self, line: str, current_year: int | None = None) -> LogEntry | None:
        """Parse one record; unrecognized and malformed lines safely return ``None``."""
        raw_line = sanitize_log_entry(line).strip()
        if not raw_line:
            return None
        header = _HEADER.match(raw_line)
        if not header:
            return None
        try:
            timestamp = self._parse_timestamp(header.group("timestamp"), current_year)
        except ValueError as error:
            logger.debug("Ignoring SSH record with invalid timestamp: %s", error)
            return None
        message = sanitize_log_entry(header.group("message"))
        parsed = self._classify(message)
        if parsed is None:
            logger.debug("Unrecognized sshd event: %s", message[:160])
            return None
        event_type, failure_type, username = parsed
        source_ip = self._extract_ip(message)
        if source_ip is None and event_type in {"authentication_failure", "authentication_success"}:
            logger.debug("Ignoring SSH authentication event without a valid source IP")
            return None
        port_match = _PORT.search(message)
        source_port = int(port_match.group(1)) if port_match else None
        if source_port is not None and not 1 <= source_port <= 65535:
            source_port = None
        pid_text = header.group("pid")
        process_id = None
        if pid_text and len(pid_text) <= 10:
            candidate_pid = int(pid_text)
            if 1 <= candidate_pid <= 2_147_483_647:
                process_id = candidate_pid
        return LogEntry(
            timestamp=timestamp,
            hostname=header.group("hostname"),
            service="sshd",
            source_ip=source_ip,
            username=username,
            failure_type=failure_type,
            raw_message=message,
            event_type=event_type,
            source_port=source_port,
            process_id=process_id,
            raw_line=raw_line,
        )

    @staticmethod
    def _parse_timestamp(value: str, current_year: int | None = None) -> datetime:
        if value[:4].isdigit():
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(
                    tzinfo=datetime.now().astimezone().tzinfo or timezone.utc
                )
            return normalize_timestamp(timestamp)
        year = current_year if current_year is not None else datetime.now().astimezone().year
        parsed = datetime.strptime(f"{value} {year}", "%b %d %H:%M:%S %Y")
        local_zone = datetime.now().astimezone().tzinfo or timezone.utc
        return normalize_timestamp(parsed.replace(tzinfo=local_zone))

    @staticmethod
    def _extract_ip(message: str) -> str | None:
        for match in _IP_CANDIDATE.finditer(message):
            candidate = match.group(1).strip("[]")
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
        return None

    @staticmethod
    def _classify(message: str) -> tuple[EventType, str, str | None] | None:
        for failure_type, pattern in _FAILURES:
            match = pattern.search(message)
            if match:
                return "authentication_failure", failure_type, match.group("username")
        for failure_type, pattern in _SUCCESSES:
            match = pattern.search(message)
            if match:
                return "authentication_success", failure_type, match.group("username")
        for failure_type, pattern in _SECURITY_EVENTS:
            if pattern.search(message):
                return "security_event", failure_type, None
        for failure_type, pattern in _CONNECTIONS:
            if pattern.search(message):
                username_match = re.search(
                    r"(?:invalid user|authenticating user)\s+(\S+)", message, re.I
                )
                return (
                    "connection",
                    failure_type,
                    username_match.group(1) if username_match else None,
                )
        return None


class LogFileReader:
    """Read appended records while detecting truncation and inode-based rotation."""

    def __init__(
        self,
        log_path: str | Path,
        initial_read: str = "end",
        max_bytes_per_poll: int = 1048576,
    ):
        if initial_read not in {"beginning", "end"}:
            raise ValueError("initial_read must be 'beginning' or 'end'")
        if (
            isinstance(max_bytes_per_poll, bool)
            or not isinstance(max_bytes_per_poll, int)
            or not 1 <= max_bytes_per_poll <= 16777216
        ):
            raise ValueError("max_bytes_per_poll must be between 1 and 16777216")
        self.log_path = Path(log_path)
        self.initial_read = initial_read
        self.max_bytes_per_poll = max_bytes_per_poll
        self.parser = SSHLogParser()
        self._handle: BinaryIO | None = None
        self._identity: tuple[int, int] | None = None
        self._pending = b""
        self._initial_read_pending = True
        self._missing_logged = False
        self._last_error: str | None = None
        self._discarding_line = False
        self._oversized_logged = False

    def _open_current(self) -> bool:
        try:
            handle = self.log_path.open("rb")
        except FileNotFoundError:
            return False
        try:
            stat_result = os.fstat(handle.fileno())
        except OSError:
            handle.close()
            raise
        identity = (stat_result.st_dev, stat_result.st_ino)
        if self._initial_read_pending and self.initial_read == "end":
            try:
                handle.seek(0, os.SEEK_END)
            except OSError:
                handle.close()
                raise
        self._handle = handle
        self._identity = identity
        self._pending = b""
        self._discarding_line = False
        self._initial_read_pending = False
        return True

    def _parse_record(self, record: bytes) -> LogEntry | None:
        if len(record) > _MAX_RECORD_BYTES:
            if not self._oversized_logged:
                logger.warning("Skipping oversized record in monitored log file %s", self.log_path)
                self._oversized_logged = True
            return None
        text = record.decode("utf-8", errors="replace").rstrip("\r")
        return self.parser.parse_line(text)

    def _read_available(self) -> list[LogEntry]:
        if self._handle is None:
            return []
        data = self._handle.read(self.max_bytes_per_poll)
        if self._discarding_line:
            newline = data.find(b"\n")
            if newline < 0:
                return []
            data = data[newline + 1 :]
            self._discarding_line = False
        combined = self._pending + data
        records = combined.split(b"\n")
        self._pending = records.pop()
        if len(self._pending) > _MAX_RECORD_BYTES:
            self._pending = b""
            self._discarding_line = True
        entries = []
        for record in records:
            entry = self._parse_record(record)
            if entry is not None:
                entries.append(entry)
        return entries

    def _flush_pending(self) -> list[LogEntry]:
        if self._discarding_line or not self._pending:
            return []
        record = self._pending
        self._pending = b""
        entry = self._parse_record(record)
        return [entry] if entry is not None else []

    def read_new_lines(self) -> list[LogEntry]:
        """Return complete new SSH events, draining the old inode on rotation."""
        entries: list[LogEntry] = []
        try:
            stat_result = None
            try:
                stat_result = self.log_path.stat()
                path_identity = (stat_result.st_dev, stat_result.st_ino)
            except FileNotFoundError:
                path_identity = None

            if path_identity is None and self._handle is None:
                if not self._missing_logged:
                    logger.warning("Monitored log file is not present: %s", self.log_path)
                    self._missing_logged = True
                self._initial_read_pending = False
                return entries
            if path_identity is not None:
                self._missing_logged = False

            if self._handle is None:
                if path_identity is not None:
                    if not self._open_current():
                        self._initial_read_pending = False
                entries.extend(self._read_available())
                self._last_error = None
                return entries

            if path_identity is not None and path_identity != self._identity:
                entries.extend(self._read_available())
                if self._handle.tell() < os.fstat(self._handle.fileno()).st_size:
                    return entries
                entries.extend(self._flush_pending())
                self._handle.close()
                self._handle = None
                self._identity = None
                self._open_current()
                entries.extend(self._read_available())
                self._last_error = None
                return entries

            if (
                path_identity is not None
                and stat_result is not None
                and stat_result.st_size < self._handle.tell()
            ):
                logger.info("Detected truncation of monitored log file %s", self.log_path)
                self._handle.seek(0)
                self._pending = b""
                self._discarding_line = False
            entries.extend(self._read_available())
            self._last_error = None
        except PermissionError:
            if self._last_error != "permission":
                logger.error("Permission denied reading monitored log file %s", self.log_path)
            self._last_error = "permission"
        except OSError as error:
            message = f"{type(error).__name__}:{error.errno}"
            if self._last_error != message:
                logger.error("Unable to read monitored log file %s: %s", self.log_path, error)
            self._last_error = message
        return entries

    def close(self) -> None:
        """Close the active file descriptor."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None
