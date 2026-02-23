"""
SSH brute-force detection engine.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from .parser import LogEntry, LogFileReader
from .utils import RollingWindow, get_hostname, calculate_attack_window


logger = logging.getLogger(__name__)


class AttackTracker:
    """
    Tracks SSH brute-force attacks per IP address.
    """
    
    def __init__(self, threshold: int = 5, window_minutes: int = 2):
        """
        Initialize attack tracker.
        
        Args:
            threshold: Number of failures to trigger alert
            window_minutes: Time window in minutes
        """
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.tracked_ips: Dict[str, RollingWindow] = defaultdict(
            lambda: RollingWindow(window_minutes)
        )
        self.alerted_ips: set = set()  # Track already-alerted IPs
    
    def add_failure(self, source_ip: str, timestamp: datetime) -> Tuple[bool, int]:
        """
        Add a failure attempt for an IP.
        
        Args:
            source_ip: Source IP address
            timestamp: Timestamp of failure
        
        Returns:
            Tuple of (is_alert_triggered, current_count)
        """
        self.tracked_ips[source_ip].add(timestamp)
        current_count = self.tracked_ips[source_ip].count()
        
        # Alert if threshold reached and not already alerted
        if current_count >= self.threshold and source_ip not in self.alerted_ips:
            self.alerted_ips.add(source_ip)
            return True, current_count
        
        return False, current_count
    
    def reset_ip(self, source_ip: str) -> None:
        """
        Reset tracking for an IP (after alert).
        
        Args:
            source_ip: Source IP address
        """
        if source_ip in self.tracked_ips:
            self.tracked_ips[source_ip].reset()
        if source_ip in self.alerted_ips:
            self.alerted_ips.remove(source_ip)
    
    def get_attempt_count(self, source_ip: str) -> int:
        """Get current attempt count for an IP."""
        if source_ip in self.tracked_ips:
            return self.tracked_ips[source_ip].count()
        return 0


class SSHBruteForceDetector:
    """
    Main SSH brute-force detection engine.
    """
    
    def __init__(self, config: dict):
        """
        Initialize detector.
        
        Args:
            config: Configuration dictionary with detection parameters
        """
        self.config = config
        self.hostname = get_hostname()
        
        # Detection parameters
        detection_config = config.get('detection', {})
        self.threshold = detection_config.get('alert_threshold', 5)
        self.window_minutes = detection_config.get('window_minutes', 2)
        
        # Initialize tracking
        self.tracker = AttackTracker(self.threshold, self.window_minutes)
        self.attack_history: List[dict] = []
        
        # Initialize log readers for both common paths
        self.log_readers = []
        for log_path in ['/var/log/auth.log', '/var/log/secure']:
            try:
                reader = LogFileReader(log_path)
                self.log_readers.append(reader)
                logger.info(f"Initialized log reader for {log_path}")
            except Exception as e:
                logger.debug(f"Could not initialize reader for {log_path}: {e}")
    
    def process_logs(self) -> List[dict]:
        """
        Process logs from all configured log files.
        
        Returns:
            List of generated alerts
        """
        alerts = []
        
        for reader in self.log_readers:
            try:
                entries = reader.read_new_lines()
                for entry in entries:
                    alert = self._process_entry(entry)
                    if alert:
                        alerts.append(alert)
            except Exception as e:
                logger.error(f"Error processing logs: {e}")
        
        return alerts
    
    def _process_entry(self, entry: LogEntry) -> Optional[dict]:
        """
        Process a single log entry.
        
        Args:
            entry: Parsed log entry
        
        Returns:
            Alert dictionary if threshold reached, None otherwise
        """
        if not entry.source_ip:
            return None
        
        # Add failure to tracker
        is_alert, attempt_count = self.tracker.add_failure(
            entry.source_ip,
            entry.timestamp
        )
        
        if is_alert:
            # Generate alert
            alert = self._generate_alert(entry, attempt_count)
            self.attack_history.append(alert)
            
            # Reset tracking after alert
            self.tracker.reset_ip(entry.source_ip)
            
            logger.warning(f"SSH Brute-Force Alert: {entry.source_ip} - {attempt_count} attempts")
            return alert
        
        return None
    
    def _generate_alert(self, entry: LogEntry, attempt_count: int) -> dict:
        """
        Generate alert JSON.
        
        Args:
            entry: Triggering log entry
            attempt_count: Number of attempts in window
        
        Returns:
            Alert dictionary
        """
        return {
            'timestamp': entry.timestamp.isoformat(),
            'source_ip': entry.source_ip,
            'username': entry.username or 'unknown',
            'attempts': attempt_count,
            'attack_type': 'SSH Brute Force',
            'severity': 'High',
            'host': self.hostname,
            'log_source': entry.service,
            'detection_window_minutes': self.window_minutes,
            'failure_types': [entry.failure_type],
        }
    
    def get_attack_history(self, limit: int = 100) -> List[dict]:
        """
        Get recent attack history.
        
        Args:
            limit: Maximum number of records
        
        Returns:
            List of recent alerts
        """
        return self.attack_history[-limit:]
    
    def shutdown(self) -> None:
        """Gracefully shutdown detector."""
        logger.info("SSH IDS detector shutting down")
