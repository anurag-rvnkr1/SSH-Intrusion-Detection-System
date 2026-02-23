#!/usr/bin/env python3
"""
SSH Attack Simulation Script
Generates realistic SSH brute-force entries to test the IDS.
"""

import sys
import os
import random
import time
from datetime import datetime, timedelta
from pathlib import Path


# Attack patterns
USERNAMES = [
    'root', 'admin', 'administrator', 'testuser', 'user', 
    'test', 'oracle', 'mysql', 'postgres', 'jenkins'
]

FAILURE_PATTERNS = [
    'Invalid user {user} from {ip}',
    'Failed password for {user} from {ip} port {port} ssh2',
    'Failed password for invalid user {user} from {ip} port {port} ssh2',
    'Failed publickey for {user} from {ip} port {port} ssh2',
    'Received disconnect from {ip} port {port} [preauth]',
    'Disconnected from {ip} port {port} [preauth]',
]

SUCCESS_PATTERN = 'Accepted password for {user} from {ip} port {port} ssh2'


class AttackSimulator:
    """Simulates SSH attacks for testing."""
    
    def __init__(self, log_file: str = '/var/log/auth.log'):
        """
        Initialize simulator.
        
        Args:
            log_file: Path to log file to write to
        """
        self.log_file = log_file
        self.start_time = datetime.now()
    
    def generate_ip(self) -> str:
        """Generate a random IP address."""
        return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    def generate_port(self) -> int:
        """Generate a random port number."""
        return random.randint(10000, 65535)
    
    def generate_timestamp(self, offset_seconds: int = 0) -> str:
        """
        Generate a syslog timestamp.
        
        Args:
            offset_seconds: Seconds to offset from now
        
        Returns:
            Syslog format timestamp
        """
        ts = self.start_time + timedelta(seconds=offset_seconds)
        return ts.strftime('%b %d %H:%M:%S')
    
    def format_log_entry(self, hostname: str, pid: int, message: str) -> str:
        """
        Format a complete log entry.
        
        Args:
            hostname: Hostname
            pid: Process ID
            message: Log message
        
        Returns:
            Formatted log entry
        """
        ts = self.generate_timestamp(random.randint(0, 300))
        return f"{ts} {hostname} sshd[{pid}]: {message}"
    
    def simulate_brute_force_attack(self, num_attempts: int = 5, 
                                   hostname: str = 'ubuntu',
                                   use_same_ip: bool = True) -> list:
        """
        Simulate a brute-force attack.
        
        Args:
            num_attempts: Number of failed attempts
            hostname: Target hostname
            use_same_ip: Use same source IP for all attempts
        
        Returns:
            List of log entries
        """
        entries = []
        attack_ip = self.generate_ip() if use_same_ip else None
        base_pid = random.randint(1000, 9999)
        
        for i in range(num_attempts):
            if not use_same_ip:
                attack_ip = self.generate_ip()
            
            # Random failure type
            pattern = random.choice(FAILURE_PATTERNS)
            user = random.choice(USERNAMES)
            port = self.generate_port()
            
            message = pattern.format(
                user=user,
                ip=attack_ip,
                port=port
            )
            
            entry = self.format_log_entry(hostname, base_pid + i, message)
            entries.append(entry)
        
        return entries
    
    def simulate_successful_login(self, hostname: str = 'ubuntu',
                                 user: str = 'validuser') -> str:
        """
        Simulate a successful login.
        
        Args:
            hostname: Target hostname
            user: Username
        
        Returns:
            Log entry
        """
        ip = self.generate_ip()
        port = self.generate_port()
        pid = random.randint(1000, 9999)
        
        message = SUCCESS_PATTERN.format(user=user, ip=ip, port=port)
        return self.format_log_entry(hostname, pid, message)
    
    def write_attacks_to_file(self, num_attacks: int = 5, 
                             attempts_per_attack: int = 5) -> None:
        """
        Write simulated attacks to log file.
        
        Args:
            num_attacks: Number of attack sequences
            attempts_per_attack: Failed attempts per attack
        """
        try:
            # Check if we have write permissions
            if not os.path.exists(self.log_file):
                print(f"Warning: Log file not found: {self.log_file}")
                print("Creating test log file instead...")
                self.log_file = '/tmp/auth_simulation.log'
            
            if not os.access(os.path.dirname(self.log_file) or '.', os.W_OK):
                print(f"Error: No write permission for {self.log_file}")
                print("Creating test log file instead...")
                self.log_file = '/tmp/auth_simulation.log'
            
            entries = []
            
            # Generate multiple attack sequences
            for _ in range(num_attacks):
                attack_entries = self.simulate_brute_force_attack(
                    num_attempts=attempts_per_attack
                )
                entries.extend(attack_entries)
                
                # Add a successful login between attacks
                success_entry = self.simulate_successful_login()
                entries.append(success_entry)
            
            # Write to file
            with open(self.log_file, 'a') as f:
                for entry in entries:
                    f.write(entry + '\n')
            
            print(f"✓ Wrote {len(entries)} simulated entries to {self.log_file}")
            
        except Exception as e:
            print(f"Error writing to log file: {e}")
            return False
        
        return True
    
    def generate_and_print(self, num_attacks: int = 3) -> None:
        """
        Generate and print attacks to stdout.
        
        Args:
            num_attacks: Number of attack sequences
        """
        for i in range(num_attacks):
            print(f"\n--- Attack Sequence {i + 1} ---")
            entries = self.simulate_brute_force_attack()
            for entry in entries:
                print(entry)
            
            print(self.simulate_successful_login())


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Simulate SSH brute-force attacks for IDS testing'
    )
    parser.add_argument(
        '--log-file',
        default='/var/log/auth.log',
        help='Log file to write attacks to (default: /var/log/auth.log)'
    )
    parser.add_argument(
        '--num-attacks',
        type=int,
        default=5,
        help='Number of attack sequences (default: 5)'
    )
    parser.add_argument(
        '--attempts-per-attack',
        type=int,
        default=5,
        help='Failed attempts per attack (default: 5)'
    )
    parser.add_argument(
        '--print-only',
        action='store_true',
        help='Print attacks to stdout instead of writing to file'
    )
    
    args = parser.parse_args()
    
    print("SSH Attack Simulator")
    print("=" * 50)
    
    simulator = AttackSimulator(args.log_file)
    
    if args.print_only:
        print(f"Generating {args.num_attacks} attack sequences...\n")
        simulator.generate_and_print(args.num_attacks)
    else:
        print(f"Simulating {args.num_attacks} attack sequences...")
        print(f"Attempts per attack: {args.attempts_per_attack}")
        print(f"Target log file: {args.log_file}\n")
        
        if simulator.write_attacks_to_file(
            num_attacks=args.num_attacks,
            attempts_per_attack=args.attempts_per_attack
        ):
            print("\nTo test the IDS with these attacks:")
            print(f"  python3 ../src/main.py ../config/config.json")
        else:
            sys.exit(1)


if __name__ == '__main__':
    main()
