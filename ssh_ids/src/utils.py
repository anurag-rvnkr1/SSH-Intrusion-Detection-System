"""Shared configuration, logging, and event-time utilities."""

from __future__ import annotations

import copy
import ipaddress
import json
import logging
import math
import os
import re
import socket
from bisect import bisect_right, insort
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PROTECTED_AUTH_LOG = re.compile(r"^(?:auth\.log(?:[-.].*)?|secure(?:[-.].*)?)$", re.I)
_MAX_DETECTION_WINDOW_MINUTES = 10080
_MAX_COOLDOWN_SECONDS = 2592000
_MAX_FUTURE_TOLERANCE_SECONDS = 86400
_MAX_POLLING_INTERVAL_SECONDS = 3600
_MAX_DELIVERY_TIMEOUT_SECONDS = 300
_MAX_RETRY_BACKOFF_SECONDS = 60
_MAX_TRACKED_IPS = 65536
_MAX_EVENTS_PER_IP = 4096
_MAX_TRACKED_EVENTS = 1_000_000
_MAX_ALERT_HISTORY = 10000
_MAX_READ_BYTES_PER_CYCLE = 64 * 1024 * 1024


def _finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and (isinstance(value, int) or math.isfinite(value))
    )


def setup_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """Return a consistently configured application logger."""
    level = getattr(logging, log_level.upper(), None)
    if not isinstance(level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    result = logging.getLogger(name)
    result.setLevel(level)
    if not result.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        result.addHandler(handler)
    return result


def _expand_environment(value: Any, location: str) -> Any:
    if isinstance(value, dict):
        return {key: _expand_environment(item, f"{location}.{key}") for key, item in value.items()}
    if isinstance(value, list):
        return [
            _expand_environment(item, f"{location}[{index}]") for index, item in enumerate(value)
        ]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ValueError(f"Environment variable {name} required by {location} is not set")
        return os.environ[name]

    return _ENV_PATTERN.sub(replace, value)


def validate_config(config: dict[str, Any], base_dir: Path | None = None) -> dict[str, Any]:
    """Validate and normalize application configuration without mutating its input."""
    if not isinstance(config, dict):
        raise ValueError("Configuration root must be a JSON object")
    normalized = _expand_environment(copy.deepcopy(config), "configuration")

    for section in ("detection", "polling", "siem"):
        if not isinstance(normalized.get(section), dict):
            raise ValueError(f"Configuration section '{section}' must be an object")

    detection = normalized["detection"]
    threshold = detection.get("alert_threshold", 5)
    window = detection.get("window_minutes", 2)
    cooldown = detection.get("cooldown_seconds", 120)
    future_tolerance = detection.get("future_tolerance_seconds", 60)
    max_ips = detection.get("max_tracked_ips", 1024)
    max_events = detection.get("max_events_per_ip", 256)
    max_alerts = detection.get("max_alert_history", 1000)
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("detection.alert_threshold must be a positive integer")
    if not _finite_number(window) or not 0 < window <= _MAX_DETECTION_WINDOW_MINUTES:
        raise ValueError("detection.window_minutes must be between 0 and 10080")
    if not _finite_number(cooldown) or not 0 <= cooldown <= _MAX_COOLDOWN_SECONDS:
        raise ValueError("detection.cooldown_seconds must be between 0 and 2592000")
    if (
        not _finite_number(future_tolerance)
        or not 0 <= future_tolerance <= _MAX_FUTURE_TOLERANCE_SECONDS
    ):
        raise ValueError("detection.future_tolerance_seconds must be between 0 and 86400")
    if (
        isinstance(max_ips, bool)
        or not isinstance(max_ips, int)
        or not 1 <= max_ips <= _MAX_TRACKED_IPS
    ):
        raise ValueError("detection.max_tracked_ips must be between 1 and 65536")
    if (
        isinstance(max_events, bool)
        or not isinstance(max_events, int)
        or not 1 <= max_events <= _MAX_EVENTS_PER_IP
    ):
        raise ValueError("detection.max_events_per_ip must be between 1 and 4096")
    if (
        isinstance(max_alerts, bool)
        or not isinstance(max_alerts, int)
        or not 1 <= max_alerts <= _MAX_ALERT_HISTORY
    ):
        raise ValueError("detection.max_alert_history must be between 1 and 10000")
    if threshold > max_events:
        raise ValueError("detection.alert_threshold cannot exceed detection.max_events_per_ip")
    if max_ips * max_events > _MAX_TRACKED_EVENTS:
        raise ValueError("Configured per-IP event capacity exceeds the global state limit")
    detection.update(
        {
            "alert_threshold": threshold,
            "window_minutes": float(window),
            "cooldown_seconds": float(cooldown),
            "future_tolerance_seconds": float(future_tolerance),
            "max_tracked_ips": max_ips,
            "max_events_per_ip": max_events,
            "max_alert_history": max_alerts,
            "log_level": str(detection.get("log_level", "INFO")).upper(),
        }
    )
    if detection["log_level"] not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("detection.log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")

    polling = normalized["polling"]
    interval = polling.get("interval_seconds", 5)
    max_bytes = polling.get("max_bytes_per_poll", 1048576)
    paths = polling.get("log_files")
    if not _finite_number(interval) or not 0 < interval <= _MAX_POLLING_INTERVAL_SECONDS:
        raise ValueError("polling.interval_seconds must be between 0 and 3600")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= 16777216
    ):
        raise ValueError("polling.max_bytes_per_poll must be an integer between 1 and 16777216")
    if (
        not isinstance(paths, list)
        or not paths
        or any(not isinstance(path, str) or not path.strip() for path in paths)
    ):
        raise ValueError("polling.log_files must be a non-empty list of path strings")
    if len(paths) > 64:
        raise ValueError("polling.log_files cannot contain more than 64 paths")
    initial_read = polling.get("initial_read", "end")
    if initial_read not in {"beginning", "end"}:
        raise ValueError("polling.initial_read must be 'beginning' or 'end'")
    root = base_dir or Path.cwd()
    resolved_paths = []
    for path in paths:
        expanded = Path(os.path.expanduser(path))
        if not expanded.is_absolute():
            expanded = root / expanded
        resolved = str(expanded.resolve())
        if resolved not in resolved_paths:
            resolved_paths.append(resolved)
    if len(resolved_paths) * max_bytes > _MAX_READ_BYTES_PER_CYCLE:
        raise ValueError("Configured log reads exceed 64 MiB per polling cycle")
    polling.update(
        {
            "interval_seconds": float(interval),
            "max_bytes_per_poll": max_bytes,
            "log_files": resolved_paths,
            "initial_read": initial_read,
        }
    )

    siem = normalized["siem"]
    for destination in ("splunk", "elk"):
        destination_config = siem.setdefault(destination, {"enabled": False})
        if not isinstance(destination_config, dict):
            raise ValueError(f"siem.{destination} must be an object")
        enabled = destination_config.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError(f"siem.{destination}.enabled must be a boolean")
        destination_config["enabled"] = enabled
        _validate_delivery_options(destination_config, f"siem.{destination}")
        if enabled:
            url = destination_config.get("url")
            parsed = urlparse(url) if isinstance(url, str) else None
            if not parsed or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"siem.{destination}.url must be an http or https URL")
            if destination == "splunk":
                token = destination_config.get("token")
                if not isinstance(token, str) or not token.strip():
                    raise ValueError(
                        "siem.splunk.token is required as a non-empty string when Splunk is enabled"
                    )
            if destination == "elk" and "headers" in destination_config:
                headers = destination_config["headers"]
                if not isinstance(headers, dict) or any(
                    not isinstance(key, str) or not isinstance(value, str)
                    for key, value in headers.items()
                ):
                    raise ValueError("siem.elk.headers must be an object of string values")

    alerts = normalized.setdefault("alerts", {})
    if not isinstance(alerts, dict):
        raise ValueError("Configuration section 'alerts' must be an object")
    local_file = alerts.get("local_file")
    if local_file is not None:
        if not isinstance(local_file, str) or not local_file.strip():
            raise ValueError("alerts.local_file must be a non-empty path string")
        alert_path = Path(os.path.expanduser(local_file))
        if not alert_path.is_absolute():
            alert_path = root / alert_path
        resolved_alert_path = alert_path.resolve()
        if is_protected_auth_log(resolved_alert_path):
            raise ValueError("alerts.local_file cannot target a system authentication log")
        alerts["local_file"] = str(resolved_alert_path)
    return normalized


def _validate_delivery_options(config: dict[str, Any], location: str) -> None:
    timeout = config.get("timeout_seconds", 5)
    attempts = config.get("max_attempts", 3)
    backoff = config.get("retry_backoff_seconds", 0.5)
    if not _finite_number(timeout) or not 0 < timeout <= _MAX_DELIVERY_TIMEOUT_SECONDS:
        raise ValueError(f"{location}.timeout_seconds must be between 0 and 300")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 10:
        raise ValueError(f"{location}.max_attempts must be an integer between 1 and 10")
    if not _finite_number(backoff) or not 0 <= backoff <= _MAX_RETRY_BACKOFF_SECONDS:
        raise ValueError(f"{location}.retry_backoff_seconds must be between 0 and 60")
    if "ssl_verify" in config and not isinstance(config["ssl_verify"], bool):
        raise ValueError(f"{location}.ssl_verify must be a boolean")


def load_config(config_path: str | Path) -> dict[str, Any]:
    """Load, expand, validate, and normalize a JSON configuration file."""
    path = Path(config_path).expanduser().resolve()
    try:
        with path.open(encoding="utf-8") as handle:
            config = json.load(handle)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {path}") from None
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in configuration file {path}: {error.msg} at line {error.lineno}"
        ) from None
    return validate_config(config, path.parent)


def get_hostname() -> str:
    """Return the local hostname, or a stable fallback if unavailable."""
    try:
        return socket.gethostname() or "unknown-host"
    except OSError:
        return "unknown-host"


def normalize_timestamp(timestamp: datetime) -> datetime:
    """Normalize a timestamp to UTC and reject timezone-naive values."""
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Event timestamps must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


def is_valid_ip(value: str) -> bool:
    """Return whether a string contains a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except (ValueError, AttributeError):
        return False


def is_protected_auth_log(path: str | Path) -> bool:
    """Identify canonical authentication logs, rotated variants, and symlink aliases."""
    candidate = Path(path).expanduser().resolve(strict=False)
    if candidate.parent == Path("/var/log") and _PROTECTED_AUTH_LOG.fullmatch(candidate.name):
        return True
    return any(
        candidate == protected.resolve(strict=False)
        for protected in (Path("/var/log/auth.log"), Path("/var/log/secure"))
    )


def sanitize_log_entry(entry: str, limit: int = 8192) -> str:
    """Remove control characters and bound untrusted log text."""
    return "".join(char for char in entry[:limit] if ord(char) >= 32 or char == "\t")


def calculate_attack_window(timestamp: datetime, window_minutes: float = 2) -> datetime:
    """Return the lower cutoff for a rolling event-time window."""
    return normalize_timestamp(timestamp) - timedelta(minutes=window_minutes)


def format_alert_timestamp(timestamp: datetime) -> str:
    """Format an aware timestamp as UTC ISO-8601."""
    return normalize_timestamp(timestamp).isoformat()


class RollingWindow:
    """Sorted, bounded event-time window; its lower boundary is exclusive."""

    def __init__(self, window_minutes: float = 2):
        if not _finite_number(window_minutes) or not 0 < window_minutes <= 10080:
            raise ValueError("window_minutes must be between 0 and 10080")
        self.window_minutes = float(window_minutes)
        self.events: list[datetime] = []
        self.latest: datetime | None = None

    def add(self, timestamp: datetime) -> bool:
        """Insert an event; reject one older than the active event-time horizon."""
        event_time = normalize_timestamp(timestamp)
        if self.latest is not None and event_time <= self.latest - timedelta(
            minutes=self.window_minutes
        ):
            return False
        self.latest = max(event_time, self.latest) if self.latest else event_time
        insort(self.events, event_time)
        self._cleanup(self.latest)
        return True

    def _cleanup(self, reference: datetime) -> None:
        cutoff = reference - timedelta(minutes=self.window_minutes)
        first_valid = bisect_right(self.events, cutoff)
        if first_valid:
            del self.events[:first_valid]

    def count(self, at: datetime | None = None) -> int:
        """Count events in ``(at - window, at]``; defaults to the latest event."""
        if at is None:
            if self.latest is None:
                return 0
            event_time = self.latest
        else:
            event_time = normalize_timestamp(at)
        cutoff = event_time - timedelta(minutes=self.window_minutes)
        return bisect_right(self.events, event_time) - bisect_right(self.events, cutoff)

    def reset(self) -> None:
        self.events.clear()
        self.latest = None
