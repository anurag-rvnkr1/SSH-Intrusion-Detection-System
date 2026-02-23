"""
SIEM integration module.
Supports Splunk HTTP Event Collector and ELK Logstash.
"""

import json
import logging
import time
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
import urllib.request
import urllib.error
from urllib.parse import urljoin


logger = logging.getLogger(__name__)


class SIEMSender(ABC):
    """Abstract base class for SIEM senders."""
    
    def __init__(self, config: Dict[str, Any], max_retries: int = 3, retry_delay: int = 2):
        """
        Initialize SIEM sender.
        
        Args:
            config: SIEM configuration
            max_retries: Maximum number of retries
            retry_delay: Delay between retries in seconds
        """
        self.config = config
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.sent_count = 0
        self.failed_count = 0
    
    @abstractmethod
    def send(self, alert: Dict[str, Any]) -> bool:
        """
        Send alert to SIEM.
        
        Args:
            alert: Alert dictionary
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    def _retry_send(self, send_func) -> bool:
        """
        Retry sending with exponential backoff.
        
        Args:
            send_func: Function to call for sending
        
        Returns:
            True if successful, False if all retries failed
        """
        for attempt in range(self.max_retries):
            try:
                result = send_func()
                if result:
                    self.sent_count += 1
                    return True
            except Exception as e:
                logger.debug(f"Attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
        
        self.failed_count += 1
        return False
    
    def get_stats(self) -> Dict[str, int]:
        """Get sending statistics."""
        return {
            'sent': self.sent_count,
            'failed': self.failed_count,
        }


class SplunkHECSender(SIEMSender):
    """
    Splunk HTTP Event Collector sender.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Splunk HEC sender.
        
        Args:
            config: Splunk configuration with 'url', 'token' required
        """
        super().__init__(config)
        self.url = config.get('url', '').rstrip('/')
        self.token = config.get('token')
        self.ssl_verify = config.get('ssl_verify', True)
        
        if not self.url or not self.token:
            raise ValueError("Splunk config requires 'url' and 'token'")
        
        # Ensure URL ends with /services/collector
        if not self.url.endswith('/services/collector'):
            self.url = urljoin(self.url, '/services/collector')
        
        logger.info(f"Initialized Splunk HEC sender: {self.url}")
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """
        Send alert to Splunk HEC.
        
        Args:
            alert: Alert dictionary
        
        Returns:
            True if successful, False otherwise
        """
        def _send_request():
            # Format event for Splunk HEC
            event = {
                'event': alert,
                'sourcetype': '_json',
                'source': 'ssh-ids',
                'host': alert.get('host', 'unknown'),
            }
            
            payload = json.dumps(event).encode('utf-8')
            
            # Create request
            req = urllib.request.Request(
                self.url,
                data=payload,
                headers={
                    'Authorization': f'Splunk {self.token}',
                    'Content-Type': 'application/json',
                }
            )
            
            # Send request
            if not self.ssl_verify:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                    status = response.status
            else:
                with urllib.request.urlopen(req, timeout=10) as response:
                    status = response.status
            
            if status in [200, 201]:
                logger.debug(f"Alert sent to Splunk: {alert['source_ip']}")
                return True
            else:
                logger.warning(f"Splunk returned status {status}")
                return False
        
        return self._retry_send(_send_request)


class ELKLogstashSender(SIEMSender):
    """
    ELK Logstash HTTP input sender.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize ELK Logstash sender.
        
        Args:
            config: Logstash configuration with 'url' required
        """
        super().__init__(config)
        self.url = config.get('url', '').rstrip('/')
        self.ssl_verify = config.get('ssl_verify', True)
        
        if not self.url:
            raise ValueError("Logstash config requires 'url'")
        
        logger.info(f"Initialized ELK Logstash sender: {self.url}")
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """
        Send alert to ELK Logstash.
        
        Args:
            alert: Alert dictionary
        
        Returns:
            True if successful, False otherwise
        """
        def _send_request():
            # ELK expects the event directly
            payload = json.dumps(alert).encode('utf-8')
            
            req = urllib.request.Request(
                self.url,
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                }
            )
            
            # Send request
            if not self.ssl_verify:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                    status = response.status
            else:
                with urllib.request.urlopen(req, timeout=10) as response:
                    status = response.status
            
            if status in [200, 201, 204]:
                logger.debug(f"Alert sent to Logstash: {alert['source_ip']}")
                return True
            else:
                logger.warning(f"Logstash returned status {status}")
                return False
        
        return self._retry_send(_send_request)


class SIEMIntegration:
    """
    Manager for multiple SIEM destinations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SIEM integration.
        
        Args:
            config: SIEM configuration from config.json
        """
        self.senders = []
        self._initialize_senders(config)
    
    def _initialize_senders(self, config: Dict[str, Any]) -> None:
        """
        Initialize configured SIEM senders.
        
        Args:
            config: SIEM configuration
        """
        # Splunk HEC
        if config.get('splunk', {}).get('enabled'):
            try:
                sender = SplunkHECSender(config['splunk'])
                self.senders.append(sender)
            except Exception as e:
                logger.error(f"Failed to initialize Splunk sender: {e}")
        
        # ELK Logstash
        if config.get('elk', {}).get('enabled'):
            try:
                sender = ELKLogstashSender(config['elk'])
                self.senders.append(sender)
            except Exception as e:
                logger.error(f"Failed to initialize ELK sender: {e}")
        
        if not self.senders:
            logger.warning("No SIEM destinations configured")
    
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Send alert to all configured SIEM destinations.
        
        Args:
            alert: Alert dictionary
        
        Returns:
            True if sent to at least one destination, False if all failed
        """
        if not self.senders:
            logger.debug("No SIEM senders configured, alert not sent")
            return False
        
        results = []
        for sender in self.senders:
            try:
                result = sender.send(alert)
                results.append(result)
            except Exception as e:
                logger.error(f"Error sending alert to SIEM: {e}")
                results.append(False)
        
        # Return True if at least one destination received the alert
        return any(results)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all senders."""
        stats = {}
        for i, sender in enumerate(self.senders):
            sender_name = sender.__class__.__name__
            stats[f'{sender_name}_{i}'] = sender.get_stats()
        return stats
