"""
Utility functions for SSH IDS system.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from functools import lru_cache


def setup_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """
    Setup and return a logger instance.
    
    Args:
        name: Logger name
        log_level: Logging level (INFO, DEBUG, WARNING, ERROR)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Console handler
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to config.json
    
    Returns:
        Configuration dictionary
    
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config is invalid JSON
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Validate required fields
    required_fields = ['detection', 'siem']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required config field: {field}")
    
    return config


def save_state(state: Dict[str, Any], state_file: str) -> None:
    """
    Save detector state to file for persistence.
    
    Args:
        state: State dictionary
        state_file: Path to state file
    """
    try:
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2, default=str)
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to save state: {e}")


def load_state(state_file: str) -> Dict[str, Any]:
    """
    Load detector state from file.
    
    Args:
        state_file: Path to state file
    
    Returns:
        State dictionary or empty dict if file doesn't exist
    """
    if not os.path.exists(state_file):
        return {}
    
    try:
        with open(state_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to load state: {e}")
        return {}


def get_hostname() -> str:
    """
    Get system hostname.
    
    Returns:
        Hostname string
    """
    try:
        return os.uname().nodename
    except Exception:
        return "unknown-host"


def is_valid_ip(ip: str) -> bool:
    """
    Validate if string is a valid IP address.
    
    Args:
        ip: IP address string
    
    Returns:
        True if valid IPv4 or IPv6, False otherwise
    """
    import re
    
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$'
    
    if re.match(ipv4_pattern, ip):
        # Validate octets are 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    if re.match(ipv6_pattern, ip.lower()):
        return True
    
    return False


def sanitize_log_entry(entry: str) -> str:
    """
    Sanitize log entry to prevent injection attacks.
    
    Args:
        entry: Raw log entry string
    
    Returns:
        Sanitized log entry
    """
    # Remove null bytes and control characters
    entry = ''.join(char for char in entry if ord(char) >= 32 or char in '\n\t')
    # Limit length to prevent buffer issues
    entry = entry[:4096]
    return entry


def calculate_attack_window(timestamp: datetime, window_minutes: int = 2) -> datetime:
    """
    Calculate the start of the attack detection window.
    
    Args:
        timestamp: Current timestamp
        window_minutes: Detection window in minutes
    
    Returns:
        Start of window timestamp
    """
    return timestamp - timedelta(minutes=window_minutes)


def format_alert_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for alert JSON.
    
    Args:
        timestamp: Datetime object
    
    Returns:
        ISO format timestamp string
    """
    return timestamp.isoformat()


class RollingWindow:
    """
    Efficient rolling window for tracking recent events.
    """
    
    def __init__(self, window_minutes: int = 2):
        """
        Initialize rolling window.
        
        Args:
            window_minutes: Window duration in minutes
        """
        self.window_minutes = window_minutes
        self.events: list = []
    
    def add(self, timestamp: datetime) -> None:
        """Add event to window."""
        self.events.append(timestamp)
        self._cleanup()
    
    def _cleanup(self) -> None:
        """Remove events outside the window."""
        cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
        self.events = [e for e in self.events if e > cutoff]
    
    def count(self) -> int:
        """Get current event count in window."""
        self._cleanup()
        return len(self.events)
    
    def reset(self) -> None:
        """Clear all events."""
        self.events = []
