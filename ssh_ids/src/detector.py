"""Event-time SSH brute-force detection and structured alert generation."""

from __future__ import annotations

import logging
import math
import uuid
from bisect import bisect_right
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .parser import LogEntry, LogFileReader
from .utils import (
    format_alert_timestamp,
    get_hostname,
    is_valid_ip,
    normalize_timestamp,
    validate_config,
)

logger = logging.getLogger(__name__)
_MAX_TRACKED_IPS = 65536
_MAX_EVENTS_PER_IP = 4096
_MAX_TRACKED_EVENTS = 1_000_000


def _finite_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and (isinstance(value, int) or math.isfinite(value))
    )


@dataclass
class _AttackState:
    events: list[_TrackedFailure] = field(default_factory=list)
    latest: datetime | None = None
    last_alert_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class _TrackedFailure:
    timestamp: datetime
    username: str | None
    failure_type: str
    source_port: int | None
    raw_line: str


class AttackTracker:
    """Track bounded per-source event-time windows and cooldown state."""

    def __init__(
        self,
        threshold: int = 5,
        window_minutes: float = 2,
        cooldown_seconds: float = 120,
        future_tolerance_seconds: float = 60,
        max_tracked_ips: int = 1024,
        max_events_per_ip: int = 256,
        clock: Callable[[], datetime] | None = None,
    ):
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or threshold < 1
            or not _finite_number(window_minutes)
            or not 0 < window_minutes <= 10080
            or not _finite_number(cooldown_seconds)
            or not 0 <= cooldown_seconds <= 2592000
            or not _finite_number(future_tolerance_seconds)
            or not 0 <= future_tolerance_seconds <= 86400
        ):
            raise ValueError("Invalid detection threshold, window, or cooldown")
        if (
            isinstance(max_tracked_ips, bool)
            or not isinstance(max_tracked_ips, int)
            or not 1 <= max_tracked_ips <= _MAX_TRACKED_IPS
            or isinstance(max_events_per_ip, bool)
            or not isinstance(max_events_per_ip, int)
            or not threshold <= max_events_per_ip <= _MAX_EVENTS_PER_IP
            or max_tracked_ips * max_events_per_ip > _MAX_TRACKED_EVENTS
        ):
            raise ValueError(
                "Tracker limits must be positive and event capacity must meet the threshold"
            )
        self.threshold = threshold
        self.window_minutes = float(window_minutes)
        self.cooldown_seconds = float(cooldown_seconds)
        self.future_tolerance_seconds = float(future_tolerance_seconds)
        self.max_tracked_ips = max_tracked_ips
        self.max_events_per_ip = max_events_per_ip
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.tracked_ips: OrderedDict[str, _AttackState] = OrderedDict()
        self._operations = 0
        self._watermark: datetime | None = None

    def add_failure(
        self, source_ip: str, timestamp: datetime, entry: LogEntry | None = None
    ) -> tuple[bool, int]:
        """Record a failure and report a threshold crossing for this event time.

        Events are accepted out of order only while they are within one active
        window of that IP's latest timestamp. Counts use ``(t-window, t]``.
        """
        try:
            event_time = normalize_timestamp(timestamp)
            now = normalize_timestamp(self.clock())
        except (AttributeError, TypeError, ValueError):
            logger.debug("Ignoring failure with invalid or timezone-naive timestamp")
            return False, 0
        if event_time > now + timedelta(seconds=self.future_tolerance_seconds):
            logger.warning("Ignoring future-dated SSH event from %s", source_ip)
            return False, self.get_attempt_count(source_ip)
        if not is_valid_ip(source_ip):
            logger.debug("Ignoring SSH failure with invalid source IP")
            return False, 0

        state = self.tracked_ips.get(source_ip)
        if state is None:
            if len(self.tracked_ips) >= self.max_tracked_ips:
                self.tracked_ips.popitem(last=False)
            state = _AttackState()
            self.tracked_ips[source_ip] = state
        else:
            self.tracked_ips.move_to_end(source_ip)

        window = timedelta(minutes=self.window_minutes)
        if state.latest is not None and event_time < state.latest - window:
            return False, len(state.events)
        cutoff = event_time - window
        state.events = [item for item in state.events if item.timestamp > cutoff]
        if entry is None:
            tracked_event = _TrackedFailure(event_time, None, "authentication_failure", None, "")
        else:
            tracked_event = _TrackedFailure(
                event_time, entry.username, entry.failure_type, entry.source_port, entry.raw_line
            )
            if entry.raw_line and any(
                item.timestamp == event_time and item.raw_line == entry.raw_line
                for item in state.events
            ):
                return False, sum(item.timestamp <= event_time for item in state.events)
            duplicate_pair = {"invalid_user", "failed_password", "failed_publickey"}
            for existing in state.events:
                paired = (
                    existing.failure_type != entry.failure_type
                    and existing.failure_type in duplicate_pair
                    and entry.failure_type in duplicate_pair
                )
                same_attempt = (
                    existing.source_port == entry.source_port
                    and existing.source_port is not None
                    and existing.username == entry.username
                    and abs((existing.timestamp - event_time).total_seconds()) <= 2
                )
                if paired and same_attempt:
                    return False, sum(item.timestamp <= event_time for item in state.events)
        event_times = [item.timestamp for item in state.events]
        index = bisect_right(event_times, event_time)
        state.events.insert(index, tracked_event)
        state.latest = max(state.latest, event_time) if state.latest else event_time
        self._watermark = max(self._watermark, event_time) if self._watermark else event_time
        if len(state.events) > self.max_events_per_ip:
            del state.events[: len(state.events) - self.max_events_per_ip]

        current_count = sum(item.timestamp <= event_time for item in state.events)
        self._operations += 1
        if self._operations % 256 == 0:
            self._cleanup_stale_states(self._watermark)

        if current_count < self.threshold:
            return False, current_count
        if state.last_alert_at is not None:
            cooldown_ends = state.last_alert_at + timedelta(seconds=self.cooldown_seconds)
            if event_time < cooldown_ends:
                return False, current_count
        state.last_alert_at = event_time
        return True, current_count

    def _cleanup_stale_states(self, watermark: datetime) -> None:
        expiry = watermark - timedelta(seconds=max(self.cooldown_seconds, self.window_minutes * 60))
        stale = [
            source_ip
            for source_ip, state in self.tracked_ips.items()
            if state.latest is not None and state.latest < expiry
        ]
        for source_ip in stale:
            self.tracked_ips.pop(source_ip, None)

    def get_attempt_count(self, source_ip: str) -> int:
        """Return the number of retained event timestamps for one source."""
        state = self.tracked_ips.get(source_ip)
        return len(state.events) if state else 0

    def get_recent_events(self, source_ip: str, at: datetime) -> list[_TrackedFailure]:
        """Return source events in the event-time window ending at ``at``."""
        state = self.tracked_ips.get(source_ip)
        if state is None:
            return []
        event_time = normalize_timestamp(at)
        cutoff = event_time - timedelta(minutes=self.window_minutes)
        return [entry for entry in state.events if cutoff < entry.timestamp <= event_time]

    def reset_ip(self, source_ip: str) -> None:
        """Remove one IP's attempt and cooldown state."""
        self.tracked_ips.pop(source_ip, None)


class SSHBruteForceDetector:
    """Read configured SSH logs, detect failure bursts, and retain alerts locally."""

    def __init__(
        self,
        config: dict,
        clock: Callable[[], datetime] | None = None,
        alert_id_factory: Callable[[], str] | None = None,
    ):
        self.config = validate_config(config, Path.cwd())
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.alert_id_factory = alert_id_factory or (lambda: str(uuid.uuid4()))
        self.hostname = get_hostname()
        detection = self.config["detection"]
        self.threshold = detection["alert_threshold"]
        self.window_minutes = detection["window_minutes"]
        self.tracker = AttackTracker(
            threshold=self.threshold,
            window_minutes=self.window_minutes,
            cooldown_seconds=detection["cooldown_seconds"],
            future_tolerance_seconds=detection["future_tolerance_seconds"],
            max_tracked_ips=detection["max_tracked_ips"],
            max_events_per_ip=detection["max_events_per_ip"],
            clock=self.clock,
        )
        self.attack_history: deque[dict] = deque(maxlen=detection["max_alert_history"])
        polling = self.config["polling"]
        self.log_readers = [
            LogFileReader(
                path,
                initial_read=polling["initial_read"],
                max_bytes_per_poll=polling["max_bytes_per_poll"],
            )
            for path in polling["log_files"]
        ]

    def process_logs(self) -> list[dict]:
        """Read all configured sources and return newly generated alerts."""
        alerts = []
        for reader in self.log_readers:
            for entry in reader.read_new_lines():
                alert = self._process_entry(entry, str(reader.log_path))
                if alert is not None:
                    alerts.append(alert)
        return alerts

    def _process_entry(self, entry: LogEntry, log_source: str = "unknown") -> dict | None:
        if not entry.is_failure or not entry.source_ip:
            return None
        should_alert, count = self.tracker.add_failure(entry.source_ip, entry.timestamp, entry)
        if not should_alert:
            return None
        alert = self._generate_alert(entry, count, log_source)
        self.attack_history.append(alert)
        logger.warning("SSH brute-force alert: %s attempts from %s", count, entry.source_ip)
        return alert

    def _generate_alert(
        self, entry: LogEntry, attempt_count: int, log_source: str = "unknown"
    ) -> dict:
        event_time = normalize_timestamp(entry.timestamp)
        recent = self.tracker.get_recent_events(entry.source_ip or "", event_time)
        failure_types = list(dict.fromkeys(item.failure_type for item in recent))
        details = [
            {
                "timestamp": format_alert_timestamp(item.timestamp),
                "username": item.username,
                "failure_type": item.failure_type,
                "source_port": item.source_port,
            }
            for item in recent[-10:]
        ]
        detected_at = normalize_timestamp(self.clock())
        return {
            "alert_id": self.alert_id_factory(),
            "timestamp": format_alert_timestamp(event_time),
            "event_timestamp": format_alert_timestamp(event_time),
            "detected_at": format_alert_timestamp(detected_at),
            "source_ip": entry.source_ip,
            "username": entry.username or "unknown",
            "attempts": attempt_count,
            "threshold": self.threshold,
            "detection_rule": "ssh_failed_authentication_burst",
            "attack_type": "SSH Brute Force",
            "severity": "High",
            "hostname": entry.hostname or self.hostname,
            "host": entry.hostname or self.hostname,
            "log_source": log_source,
            "detection_window_minutes": self.window_minutes,
            "failure_types": failure_types,
            "event_details": details,
        }

    def get_attack_history(self, limit: int = 100) -> list[dict]:
        """Return the newest locally recorded alerts."""
        if limit <= 0:
            return []
        return list(self.attack_history)[-limit:]

    def shutdown(self) -> None:
        """Close all monitored file handles."""
        for reader in self.log_readers:
            reader.close()
        logger.info("SSH IDS detector shut down")
