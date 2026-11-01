"""HTTP delivery integrations for Splunk HEC and Logstash."""

from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger(__name__)
_RETRYABLE_STATUSES = {408, 425, 429}
_MAX_HEC_RESPONSE_BYTES = 8192


class SIEMSender(ABC):
    """Shared bounded retry and HTTP handling for SIEM destinations."""

    def __init__(self, config: dict[str, Any], success_statuses: set[int]):
        self.config = config
        self.max_attempts = config.get("max_attempts", 3)
        self.timeout_seconds = config.get("timeout_seconds", 5)
        self.retry_backoff_seconds = config.get("retry_backoff_seconds", 0.5)
        self.ssl_verify = config.get("ssl_verify", True)
        self.success_statuses = success_statuses
        self.url = ""
        self.sent_count = 0
        self.failed_count = 0
        self.destination = "SIEM"

    @abstractmethod
    def send(self, alert: dict[str, Any]) -> bool:
        """Send an alert, returning whether this destination accepted it."""

    def _validate_success_response(self, response: Any) -> bool:
        """Validate destination-specific details after an accepted HTTP status."""
        return True

    def _deliver(self, payload: bytes, headers: dict[str, str]) -> bool:
        if urlsplit(self.url).scheme not in {"http", "https"}:
            logger.warning("%s delivery rejected: unsupported URL scheme", self.destination)
            self.failed_count += 1
            return False
        request = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        context = None
        if self.url.startswith("https://") and not self.ssl_verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        for attempt in range(self.max_attempts):
            valid_response = False
            try:
                # The scheme guard above prevents urllib from opening local or custom schemes.
                with urllib.request.urlopen(
                    request, timeout=self.timeout_seconds, context=context
                ) as response:  # nosec B310
                    status = response.status
                    if status in self.success_statuses:
                        valid_response = self._validate_success_response(response)
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt + 1 < self.max_attempts:
                    self._wait(attempt)
                    continue
                logger.warning("%s delivery failed after network errors", self.destination)
                self.failed_count += 1
                return False

            if status in self.success_statuses:
                if not valid_response:
                    logger.warning(
                        "%s returned an invalid success response; alert was not delivered",
                        self.destination,
                    )
                    self.failed_count += 1
                    return False
                self.sent_count += 1
                return True
            if status in _RETRYABLE_STATUSES or 500 <= status <= 599:
                if attempt + 1 < self.max_attempts:
                    self._wait(attempt)
                    continue
            logger.warning("%s returned HTTP %s; alert was not delivered", self.destination, status)
            self.failed_count += 1
            return False

        self.failed_count += 1
        return False

    def _wait(self, attempt: int) -> None:
        delay = min(self.retry_backoff_seconds * (2**attempt), 30.0)
        if delay:
            time.sleep(delay)

    def get_stats(self) -> dict[str, int]:
        """Return delivery counters."""
        return {"sent": self.sent_count, "failed": self.failed_count}


class SplunkHECSender(SIEMSender):
    """Send structured events to the Splunk HTTP Event Collector."""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config, {200, 201})
        self.destination = "Splunk HEC"
        self.url = config["url"].rstrip("/")
        if not self.url.endswith("/services/collector"):
            self.url = urljoin(self.url + "/", "services/collector")
        self.token = config["token"]

    def _validate_success_response(self, response: Any) -> bool:
        try:
            body = response.read(_MAX_HEC_RESPONSE_BYTES + 1)
            if len(body) > _MAX_HEC_RESPONSE_BYTES:
                return False
            result = json.loads(body)
        except (AttributeError, OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(result, dict) and type(result.get("code")) is int and result["code"] == 0

    def send(self, alert: dict[str, Any]) -> bool:
        envelope = {
            "event": alert,
            "sourcetype": "_json",
            "source": "ssh-ids",
            "host": alert.get("host", "unknown"),
        }
        payload = json.dumps(envelope, separators=(",", ":"), allow_nan=False).encode("utf-8")
        return self._deliver(
            payload,
            {
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
        )


class ELKLogstashSender(SIEMSender):
    """Post one JSON event to a Logstash HTTP input."""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config, {200, 201, 202, 204})
        self.destination = "Logstash"
        self.url = config["url"]
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(config.get("headers", {}))

    def send(self, alert: dict[str, Any]) -> bool:
        payload = json.dumps(alert, separators=(",", ":"), allow_nan=False).encode("utf-8")
        return self._deliver(payload, self.headers)


class SIEMIntegration:
    """Dispatch alerts independently to all enabled SIEM destinations."""

    def __init__(self, config: dict[str, Any]):
        self.senders: list[SIEMSender] = []
        if config.get("splunk", {}).get("enabled", False):
            self.senders.append(SplunkHECSender(config["splunk"]))
        if config.get("elk", {}).get("enabled", False):
            self.senders.append(ELKLogstashSender(config["elk"]))
        if not self.senders:
            logger.info("SIEM delivery is disabled; alerts will remain in local logs")

    def send_alert(self, alert: dict[str, Any]) -> bool | None:
        """Return ``None`` if disabled, otherwise true only if all destinations succeed."""
        if not self.senders:
            return None
        results = []
        for sender in self.senders:
            try:
                results.append(sender.send(alert))
            except (TypeError, ValueError, UnicodeError) as error:
                logger.error(
                    "%s could not serialize alert (%s)", sender.destination, type(error).__name__
                )
                sender.failed_count += 1
                results.append(False)
            except Exception as error:
                logger.error("%s delivery failed (%s)", sender.destination, type(error).__name__)
                sender.failed_count += 1
                results.append(False)
        return all(results)

    def get_stats(self) -> dict[str, dict[str, int]]:
        """Return per-destination counters."""
        return {
            f"{sender.destination}_{index}": sender.get_stats()
            for index, sender in enumerate(self.senders, start=1)
        }
