#!/usr/bin/env python3
"""
SSH Intrusion Detection System - Main Application
Monitors SSH logs and forwards alerts to SIEM.
"""

import sys
import os
import signal
import time
import json
import logging
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from detector import SSHBruteForceDetector
from sender import SIEMIntegration
from utils import setup_logger, load_config


class SSHIDSApplication:
    """
    Main SSH IDS application.
    """
    
    def __init__(self, config_path: str):
        """
        Initialize application.
        
        Args:
            config_path: Path to config.json
        """
        # Load configuration
        self.config = load_config(config_path)
        
        # Setup logging
        log_level = self.config.get('detection', {}).get('log_level', 'INFO')
        self.logger = setup_logger('ssh-ids', log_level)
        
        # Initialize detector
        self.detector = SSHBruteForceDetector(self.config)
        self.logger.info("SSH IDS detector initialized")
        
        # Initialize SIEM integration
        self.siem = SIEMIntegration(self.config.get('siem', {}))
        
        # Polling configuration
        self.polling_interval = self.config.get('polling', {}).get('interval_seconds', 5)
        
        # Running state
        self.running = False
        self.stats = {
            'processed_alerts': 0,
            'sent_alerts': 0,
            'failed_sends': 0,
            'start_time': None,
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def run(self) -> None:
        """
        Main application loop.
        """
        self.running = True
        self.stats['start_time'] = time.time()
        self.logger.info("SSH IDS application started")
        
        try:
            while self.running:
                try:
                    # Process logs and get alerts
                    alerts = self.detector.process_logs()
                    self.stats['processed_alerts'] += len(alerts)
                    
                    # Send alerts to SIEM
                    for alert in alerts:
                        if self.siem.send_alert(alert):
                            self.stats['sent_alerts'] += 1
                            self._log_alert(alert)
                        else:
                            self.stats['failed_sends'] += 1
                    
                    # Wait before next poll
                    time.sleep(self.polling_interval)
                
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}", exc_info=True)
                    time.sleep(self.polling_interval)
        
        finally:
            self.shutdown()
    
    def _log_alert(self, alert: dict) -> None:
        """
        Log alert details.
        
        Args:
            alert: Alert dictionary
        """
        self.logger.warning(
            f"SSH BRUTE-FORCE DETECTED: "
            f"Source IP={alert['source_ip']}, "
            f"Attempts={alert['attempts']}, "
            f"User={alert['username']}"
        )
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def shutdown(self) -> None:
        """Gracefully shutdown application."""
        self.logger.info("Shutting down SSH IDS")
        
        # Stop detector
        self.detector.shutdown()
        
        # Log final statistics
        runtime = time.time() - self.stats['start_time']
        self.logger.info(
            f"Statistics: "
            f"Alerts Generated={self.stats['processed_alerts']}, "
            f"Alerts Sent={self.stats['sent_alerts']}, "
            f"Failed Sends={self.stats['failed_sends']}, "
            f"Runtime={runtime:.1f}s"
        )
        
        self.running = False


def main():
    """
    Main entry point.
    """
    # Determine config path
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        # Default to config/config.json relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, '..', 'config', 'config.json')
    
    # Verify config exists
    if not os.path.exists(config_path):
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        print(f"Usage: python3 main.py [config_path]", file=sys.stderr)
        sys.exit(1)
    
    # Run application
    try:
        app = SSHIDSApplication(config_path)
        app.run()
        sys.exit(0)
    except Exception as e:
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
