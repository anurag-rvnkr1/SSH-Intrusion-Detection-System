#!/usr/bin/env python3
"""Canonical CLI entry point for the SSH intrusion detection system."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Sequence

from .alert_store import LocalAlertStore
from .detector import SSHBruteForceDetector
from .sender import SIEMIntegration
from .utils import is_protected_auth_log, load_config, setup_logger

__version__ = "1.0.0"
_DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "config.json"


class SSHIDSApplication:
    """Coordinate configured log readers, local alerts, and optional SIEM delivery."""

    def __init__(
        self,
        config_path: str | Path,
        log_file: str | Path | None = None,
        test_mode: bool = False,
        verbose: bool = False,
    ):
        self.config = load_config(config_path)
        if log_file is not None:
            path = Path(log_file).expanduser().resolve()
            self.config["polling"]["log_files"] = [str(path)]
        if test_mode:
            if any(is_protected_auth_log(path) for path in self.config["polling"]["log_files"]):
                raise ValueError(
                    "--test-mode requires a dedicated test log, not a system authentication log"
                )
            self.config["polling"]["initial_read"] = "beginning"
        log_level = "DEBUG" if verbose else self.config["detection"]["log_level"]
        self.logger = setup_logger("ssh_ids", log_level)
        self.detector = SSHBruteForceDetector(self.config)
        self.siem = SIEMIntegration(self.config["siem"])
        alert_path = self.config["alerts"].get("local_file")
        self.alert_store = LocalAlertStore(alert_path) if alert_path else None
        self.polling_interval = self.config["polling"]["interval_seconds"]
        self.test_mode = test_mode
        self._stop = threading.Event()
        self._start_time: float | None = None
        self.stats = {
            "processed_alerts": 0,
            "sent_alerts": 0,
            "failed_sends": 0,
        }

    def run(self) -> int:
        """Monitor until signalled; always close readers and report final counters."""
        self._start_time = time.monotonic()
        self.logger.info(
            "Starting %s; monitoring: %s",
            "local test logs" if self.test_mode else "configured authentication logs",
            ", ".join(self.config["polling"]["log_files"]),
        )
        self.logger.info(
            "SIEM destinations: %s",
            ", ".join(sender.destination for sender in self.siem.senders) or "disabled",
        )
        previous_handlers = {}
        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self._signal_handler)
            while not self._stop.is_set():
                alerts = self.detector.process_logs()
                self.stats["processed_alerts"] += len(alerts)
                for alert in alerts:
                    self._log_alert(alert)
                    result = self.siem.send_alert(alert)
                    if result is True:
                        self.stats["sent_alerts"] += 1
                    elif result is False:
                        self.stats["failed_sends"] += 1
                self._stop.wait(self.polling_interval)
            return 0
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested")
            return 0
        except (OSError, ValueError) as error:
            self.logger.error("Application stopped: %s", error)
            return 1
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            self.shutdown()

    def _log_alert(self, alert: dict) -> None:
        """Record every generated alert locally, regardless of SIEM status."""
        if self.alert_store is not None:
            try:
                self.alert_store.append(alert)
            except (OSError, ValueError, TypeError) as error:
                self.logger.error("Unable to persist local alert (%s)", type(error).__name__)
        self.logger.warning("SSH IDS alert: %s", json.dumps(alert, sort_keys=True))

    def _signal_handler(self, signum: int, _frame: object) -> None:
        self.logger.info("Received signal %s; shutting down", signum)
        self._stop.set()

    def shutdown(self) -> None:
        """Close resources and emit final delivery statistics."""
        self.detector.shutdown()
        runtime = time.monotonic() - self._start_time if self._start_time is not None else 0.0
        self.logger.info(
            "Statistics: alerts=%d delivered=%d failed_deliveries=%d runtime=%.1fs",
            self.stats["processed_alerts"],
            self.stats["sent_alerts"],
            self.stats["failed_sends"],
            runtime,
        )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor SSH logs and detect brute-force activity."
    )
    parser.add_argument(
        "--config", type=Path, default=_DEFAULT_CONFIG, help="JSON configuration file"
    )
    parser.add_argument(
        "--test-mode", action="store_true", help="Read dedicated local test logs from the beginning"
    )
    parser.add_argument(
        "--log-file", type=Path, help="Monitor this single log instead of configured paths"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        app = SSHIDSApplication(
            args.config,
            log_file=args.log_file,
            test_mode=args.test_mode,
            verbose=args.verbose,
        )
        return app.run()
    except (OSError, ValueError) as error:
        logging.getLogger("ssh_ids").error("Unable to start: %s", error)
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
