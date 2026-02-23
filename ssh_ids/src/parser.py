"""
Log parsing module for SSH authentication logs.
Handles /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS/Kali).
"""

import re
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from .utils import sanitize_log_entry, is_valid_ip


logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Parsed log entry."""
    timestamp: datetime
    hostname: str
    service: str
    source_ip: Optional[str]
    username: Optional[str]
    failure_type: str
    raw_message: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'hostname': self.hostname,
            'service': self.service,
            'source_ip': self.source_ip,
            'username': self.username,
            'failure_type': self.failure_type,
        }


class SSHLogParser:
    """
    Parser for SSH authentication logs.
    """
    
    # Regex patterns for different failure types
    PATTERNS = {
        'invalid_user': (
            r'Invalid user\s+(\S+)\s+from\s+([0-9a-f:.]+)',
            ['username', 'source_ip']
        ),
        'failed_password': (
            r'Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9a-f:.]+)',
            ['username', 'source_ip']
        ),
        'failed_publickey': (
            r'Failed publickey for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9a-f:.]+)',
            ['username', 'source_ip']
        ),
        'no_matching_cipher': (
            r'no matching cipher found: client.*from\s+([0-9a-f:.]+)',
            ['source_ip']
        ),
        'connection_closed': (
            r'Connection closed by\s+(?:invalid user\s+)?(\S+)?\s*([0-9a-f:.]+)',
            ['username', 'source_ip']
        ),
        'disconnected_auth_timeout': (
            r'Disconnected from\s+(?:invalid user\s+)?(\S+)?\s*([0-9a-f:.]+)\s+port.*\[preauth\]',
            ['username', 'source_ip']
        ),
        'received_disconnect': (
            r'Received disconnect from\s+([0-9a-f:.]+).*\[preauth\]',
            ['source_ip']
        ),
        'invalid_format': (
            r'Bad protocol version identification.*from\s+([0-9a-f:.]+)',
            ['source_ip']
        ),
    }
    
    # Standard syslog timestamp format (used by most Linux systems)
    TIMESTAMP_FORMATS = [
        '%b %d %H:%M:%S',      # Standard syslog: Jan 15 10:30:45
        '%b  %d %H:%M:%S',     # With extra space for single digit day
        '%Y-%m-%d %H:%M:%S',   # ISO format
    ]
    
    def __init__(self):
        """Initialize parser."""
        self.compiled_patterns = {}
        for name, (pattern, fields) in self.PATTERNS.items():
            self.compiled_patterns[name] = (re.compile(pattern), fields)
    
    def parse_line(self, line: str, current_year: Optional[int] = None) -> Optional[LogEntry]:
        """
        Parse a single log line.
        
        Args:
            line: Raw log line
            current_year: Current year for timestamp parsing (defaults to current)
        
        Returns:
            Parsed LogEntry or None if line doesn't match
        """
        line = sanitize_log_entry(line)
        
        if not line.strip():
            return None
        
        try:
            # Parse standard syslog format: hostname[pid]: message
            # Example: ubuntu sshd[1234]: Invalid user admin from 192.168.1.1
            match = re.match(
                r'(\S+)\s+(.+?)\s+sshd\[(\d+)\]:\s+(.+)',
                line
            )
            
            if not match:
                return None
            
            hostname = match.group(1)
            timestamp_str = match.group(2)
            message = match.group(4)
            
            # Parse timestamp
            timestamp = self._parse_timestamp(timestamp_str, current_year)
            if not timestamp:
                return None
            
            # Try to match against failure patterns
            failure_data = self._match_patterns(message)
            if not failure_data:
                return None
            
            failure_type, source_ip, username = failure_data
            
            # Validate IP address
            if source_ip and not is_valid_ip(source_ip):
                return None
            
            return LogEntry(
                timestamp=timestamp,
                hostname=hostname,
                service='sshd',
                source_ip=source_ip,
                username=username,
                failure_type=failure_type,
                raw_message=message
            )
        
        except Exception as e:
            logger.debug(f"Failed to parse line: {line[:50]}... - {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str, current_year: Optional[int] = None) -> Optional[datetime]:
        """
        Parse timestamp string.
        
        Args:
            timestamp_str: Timestamp string from log
            current_year: Current year (for syslog format without year)
        
        Returns:
            Parsed datetime or None
        """
        if current_year is None:
            current_year = datetime.now().year
        
        # Try different timestamp formats
        for fmt in self.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(timestamp_str.strip(), fmt)
                # Add year if not present in format
                if dt.year == 1900:
                    dt = dt.replace(year=current_year)
                return dt
            except ValueError:
                continue
        
        return None
    
    def _match_patterns(self, message: str) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
        """
        Match message against failure patterns.
        
        Args:
            message: Log message
        
        Returns:
            Tuple of (failure_type, source_ip, username) or None
        """
        for failure_type, (pattern, fields) in self.compiled_patterns.items():
            match = pattern.search(message)
            if match:
                groups = match.groups()
                source_ip = None
                username = None
                
                # Map captured groups to fields
                for i, field in enumerate(fields):
                    if i < len(groups) and groups[i]:
                        if field == 'source_ip':
                            source_ip = groups[i]
                        elif field == 'username':
                            username = groups[i]
                
                return (failure_type, source_ip, username)
        
        return None


class LogFileReader:
    """
    Efficient log file reader with file rotation support.
    """
    
    def __init__(self, log_path: str):
        """
        Initialize log file reader.
        
        Args:
            log_path: Path to log file
        """
        self.log_path = log_path
        self.position = 0
        self.inode = None
        self.parser = SSHLogParser()
    
    def read_new_lines(self) -> list:
        """
        Read new lines from log file since last read.
        Handles file rotation transparently.
        
        Returns:
            List of LogEntry objects
        """
        entries = []
        
        try:
            # Check if file exists
            if not os.path.exists(self.log_path):
                logger.warning(f"Log file not found: {self.log_path}")
                return entries
            
            # Get current inode
            stat = os.stat(self.log_path)
            current_inode = stat.st_ino
            
            # Detect file rotation (inode changed)
            if self.inode is not None and self.inode != current_inode:
                logger.info(f"Log file rotated detected for {self.log_path}")
                self.position = 0
            
            self.inode = current_inode
            
            # Read new lines
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to last position
                f.seek(self.position)
                
                # Read new lines
                for line in f:
                    entry = self.parser.parse_line(line.strip())
                    if entry:
                        entries.append(entry)
                
                # Update position
                self.position = f.tell()
        
        except PermissionError:
            logger.error(f"Permission denied reading log file: {self.log_path}")
        except Exception as e:
            logger.error(f"Error reading log file {self.log_path}: {e}")
        
        return entries


# Import os at module level
import os
