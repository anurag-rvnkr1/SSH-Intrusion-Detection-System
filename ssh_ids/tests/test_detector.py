#!/usr/bin/env python3
"""
Unit tests for SSH IDS detector.
"""

import sys
import os
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from parser import SSHLogParser, LogEntry, LogFileReader
from detector import AttackTracker, SSHBruteForceDetector
from utils import RollingWindow, is_valid_ip, sanitize_log_entry


class TestLogParser(unittest.TestCase):
    """Test log parsing functionality."""
    
    def setUp(self):
        self.parser = SSHLogParser()
    
    def test_parse_invalid_user(self):
        """Test parsing invalid user attempts."""
        line = "Feb 15 10:15:23 ubuntu sshd[1234]: Invalid user admin from 192.168.1.100"
        entry = self.parser.parse_line(line, current_year=2024)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, 'admin')
        self.assertEqual(entry.source_ip, '192.168.1.100')
        self.assertEqual(entry.failure_type, 'invalid_user')
    
    def test_parse_failed_password(self):
        """Test parsing failed password attempts."""
        line = "Feb 15 10:15:24 ubuntu sshd[1235]: Failed password for root from 192.168.1.101 port 54321 ssh2"
        entry = self.parser.parse_line(line, current_year=2024)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, 'root')
        self.assertEqual(entry.source_ip, '192.168.1.101')
        self.assertEqual(entry.failure_type, 'failed_password')
    
    def test_parse_invalid_format(self):
        """Test parsing invalid format attempts."""
        line = "Feb 15 10:17:01 ubuntu sshd[1257]: Bad protocol version identification \"SSH-2.0-INVALID\" from 192.168.1.104 port 57001"
        entry = self.parser.parse_line(line, current_year=2024)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, '192.168.1.104')
        self.assertEqual(entry.failure_type, 'invalid_format')
    
    def test_parse_invalid_line(self):
        """Test that non-matching lines return None."""
        line = "Feb 15 10:15:23 ubuntu kernel: Some kernel message"
        entry = self.parser.parse_line(line)
        
        self.assertIsNone(entry)
    
    def test_parse_empty_line(self):
        """Test that empty lines return None."""
        entry = self.parser.parse_line("")
        self.assertIsNone(entry)


class TestAttackTracker(unittest.TestCase):
    """Test attack tracking functionality."""
    
    def setUp(self):
        self.tracker = AttackTracker(threshold=5, window_minutes=2)
    
    def test_threshold_alert(self):
        """Test that alert is triggered at threshold."""
        now = datetime.now()
        
        # Add 4 failures
        for i in range(4):
            is_alert, count = self.tracker.add_failure('192.168.1.100', now - timedelta(seconds=i))
            self.assertFalse(is_alert)
            self.assertEqual(count, i + 1)
        
        # 5th failure should trigger alert
        is_alert, count = self.tracker.add_failure('192.168.1.100', now)
        self.assertTrue(is_alert)
        self.assertEqual(count, 5)
    
    def test_no_double_alert(self):
        """Test that same IP doesn't trigger multiple alerts."""
        now = datetime.now()
        
        # Trigger first alert
        for i in range(5):
            self.tracker.add_failure('192.168.1.100', now - timedelta(seconds=i))
        
        # Add more failures from same IP
        is_alert, count = self.tracker.add_failure('192.168.1.100', now + timedelta(seconds=1))
        self.assertFalse(is_alert)  # Should not alert again
    
    def test_ip_reset(self):
        """Test that IP tracking can be reset."""
        now = datetime.now()
        
        # Trigger alert
        for i in range(5):
            self.tracker.add_failure('192.168.1.100', now - timedelta(seconds=i))
        
        # Reset IP
        self.tracker.reset_ip('192.168.1.100')
        
        # Should be able to alert again after reset
        is_alert, count = self.tracker.add_failure('192.168.1.100', now + timedelta(minutes=1))
        self.assertFalse(is_alert)
        self.assertEqual(count, 1)


class TestRollingWindow(unittest.TestCase):
    """Test rolling window tracking."""
    
    def test_window_add_and_count(self):
        """Test adding events to window."""
        window = RollingWindow(window_minutes=2)
        now = datetime.now()
        
        window.add(now - timedelta(seconds=30))
        window.add(now - timedelta(seconds=20))
        window.add(now)
        
        self.assertEqual(window.count(), 3)
    
    def test_window_cleanup(self):
        """Test that old events are cleaned up."""
        window = RollingWindow(window_minutes=2)
        now = datetime.now()
        
        # Add old event (outside window)
        window.add(now - timedelta(minutes=3))
        self.assertEqual(window.count(), 0)  # Cleaned up
        
        # Add recent event
        window.add(now)
        self.assertEqual(window.count(), 1)
    
    def test_window_reset(self):
        """Test window reset."""
        window = RollingWindow()
        now = datetime.now()
        
        window.add(now)
        window.add(now)
        self.assertEqual(window.count(), 2)
        
        window.reset()
        self.assertEqual(window.count(), 0)


class TestUtilities(unittest.TestCase):
    """Test utility functions."""
    
    def test_valid_ipv4(self):
        """Test IPv4 validation."""
        self.assertTrue(is_valid_ip('192.168.1.1'))
        self.assertTrue(is_valid_ip('10.0.0.1'))
        self.assertTrue(is_valid_ip('255.255.255.255'))
    
    def test_invalid_ipv4(self):
        """Test invalid IPv4 detection."""
        self.assertFalse(is_valid_ip('256.1.1.1'))
        self.assertFalse(is_valid_ip('not.an.ip.address'))
        self.assertFalse(is_valid_ip(''))
    
    def test_ipv6(self):
        """Test IPv6 validation."""
        self.assertTrue(is_valid_ip('::1'))
        self.assertTrue(is_valid_ip('2001:db8::1'))
    
    def test_sanitize_log_entry(self):
        """Test log entry sanitization."""
        entry = "Normal log entry"
        self.assertEqual(sanitize_log_entry(entry), entry)
        
        # Test with control characters
        entry_with_nulls = "Log\x00entry\x01test"
        sanitized = sanitize_log_entry(entry_with_nulls)
        self.assertNotIn('\x00', sanitized)
        self.assertNotIn('\x01', sanitized)
    
    def test_sanitize_length_limit(self):
        """Test that long entries are truncated."""
        long_entry = "A" * 5000
        sanitized = sanitize_log_entry(long_entry)
        self.assertEqual(len(sanitized), 4096)


class TestSSHBruteForceDetector(unittest.TestCase):
    """Test SSH brute-force detector."""
    
    def setUp(self):
        self.config = {
            'detection': {
                'alert_threshold': 5,
                'window_minutes': 2,
            },
            'siem': {}
        }
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        detector = SSHBruteForceDetector(self.config)
        self.assertIsNotNone(detector)
        self.assertEqual(detector.threshold, 5)
        self.assertEqual(detector.window_minutes, 2)
    
    def test_alert_generation(self):
        """Test alert generation."""
        detector = SSHBruteForceDetector(self.config)
        
        # Create log entry
        entry = LogEntry(
            timestamp=datetime.now(),
            hostname='ubuntu',
            service='sshd',
            source_ip='192.168.1.100',
            username='root',
            failure_type='invalid_user',
            raw_message='Test message'
        )
        
        # Generate alert
        alert = detector._generate_alert(entry, 5)
        
        self.assertEqual(alert['source_ip'], '192.168.1.100')
        self.assertEqual(alert['username'], 'root')
        self.assertEqual(alert['attempts'], 5)
        self.assertEqual(alert['attack_type'], 'SSH Brute Force')
        self.assertEqual(alert['severity'], 'High')


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    def test_sample_log_parsing(self):
        """Test parsing sample auth.log file."""
        test_dir = os.path.dirname(os.path.abspath(__file__))
        log_file = os.path.join(test_dir, 'sample_auth.log')
        
        if not os.path.exists(log_file):
            self.skipTest(f"Sample log file not found: {log_file}")
        
        parser = SSHLogParser()
        parsed_count = 0
        
        with open(log_file, 'r') as f:
            for line in f:
                entry = parser.parse_line(line.strip(), current_year=2024)
                if entry:
                    parsed_count += 1
        
        # Should parse multiple entries
        self.assertGreater(parsed_count, 0)
        print(f"Parsed {parsed_count} entries from sample log")


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestLogParser))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackTracker))
    suite.addTests(loader.loadTestsFromTestCase(TestRollingWindow))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilities))
    suite.addTests(loader.loadTestsFromTestCase(TestSSHBruteForceDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
