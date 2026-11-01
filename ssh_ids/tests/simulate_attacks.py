#!/usr/bin/env python3
"""Generate local SSH log fixtures; this utility never creates network traffic."""

from __future__ import annotations

import argparse
import ipaddress
import math
import os
import random
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ssh_ids.src.utils import is_protected_auth_log  # noqa: E402

DEFAULT_OUTPUT = Path(tempfile.gettempdir()) / "ssh-ids-test" / "auth_simulation.log"
MAX_SIMULATED_RECORDS = 100_000
USERNAMES = (
    "root",
    "admin",
    "administrator",
    "testuser",
    "user",
    "test",
    "oracle",
    "mysql",
    "postgres",
    "jenkins",
)
FAILURE_PATTERNS = (
    "Invalid user {user} from {ip} port {port}",
    "Failed password for {user} from {ip} port {port} ssh2",
    "Failed password for invalid user {user} from {ip} port {port} ssh2",
    "Failed publickey for {user} from {ip} port {port} ssh2",
)


def _validate_output(path: Path) -> Path:
    original = path.expanduser().absolute()
    resolved = original.resolve(strict=False)
    if is_protected_auth_log(resolved):
        raise ValueError(f"Refusing to write to protected authentication log: {resolved}")
    if original.is_symlink() or any(
        parent.is_symlink() for parent in original.parents if parent != Path("/")
    ):
        raise ValueError(f"Refusing to write through a symlink: {original}")
    return resolved


class AttackSimulator:
    """Build deterministic, chronological SSH records for isolated test files."""

    def __init__(
        self,
        log_file: str | Path = DEFAULT_OUTPUT,
        seed: int | None = None,
        start_time: datetime | None = None,
    ):
        self.log_file = _validate_output(Path(log_file))
        self.random = random.Random(seed)
        if start_time is None and seed is not None:
            now = datetime.now(timezone.utc)
            start_time = datetime(max(1, now.year - 1), 12, 31, tzinfo=timezone.utc)
        self.start_time = self._normalize_time(start_time or datetime.now(timezone.utc))

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("start_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    def _format_entry(self, timestamp: datetime, hostname: str, pid: int, message: str) -> str:
        stamp = timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")
        return f"{stamp} {hostname} sshd[{pid}]: {message}"

    def generate_entries(
        self,
        num_attacks: int = 1,
        attempts_per_attack: int = 5,
        hostname: str = "ubuntu",
        source_ips: Sequence[str] | None = None,
        usernames: Sequence[str] | None = None,
        scenario: str = "brute-force",
        window_seconds: float = 120,
    ) -> list[str]:
        """Generate attacks without writing files or creating network traffic."""
        if (
            isinstance(num_attacks, bool)
            or not isinstance(num_attacks, int)
            or num_attacks < 1
            or isinstance(attempts_per_attack, bool)
            or not isinstance(attempts_per_attack, int)
            or attempts_per_attack < 1
        ):
            raise ValueError("Attack count and attempts must be positive integers")
        if num_attacks * attempts_per_attack > MAX_SIMULATED_RECORDS:
            raise ValueError(f"Generated record count cannot exceed {MAX_SIMULATED_RECORDS}")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not (isinstance(window_seconds, int) or math.isfinite(window_seconds))
            or not 0 < window_seconds <= 604800
        ):
            raise ValueError("window_seconds must be between 0 and 604800")
        if scenario not in {"brute-force", "successful-login", "preauth-scan"}:
            raise ValueError(f"Unsupported scenario: {scenario}")
        if (
            not isinstance(hostname, str)
            or not hostname
            or len(hostname) > 255
            or not hostname.isprintable()
            or any(char.isspace() for char in hostname)
        ):
            raise ValueError(
                "hostname must be a printable, non-empty value of at most 255 characters"
            )
        ip_values = list(source_ips or ())
        for value in ip_values:
            if not isinstance(value, str):
                raise ValueError("Source IP addresses must be strings")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError(f"Invalid source IP address: {value}") from None
        user_values = list(usernames or USERNAMES)
        if not user_values or any(
            not isinstance(user, str)
            or not user
            or len(user) > 256
            or not user.isprintable()
            or any(char.isspace() for char in user)
            for user in user_values
        ):
            raise ValueError(
                "Usernames must be printable, non-empty values of at most 256 characters"
            )

        result = []
        seconds_between_attempts = min(1.0, window_seconds / attempts_per_attack)
        for attack_index in range(num_attacks):
            source_ip = (
                ip_values[attack_index % len(ip_values)]
                if ip_values
                else f"198.51.100.{self.random.randint(1, 254)}"
            )
            sequence_start = self.start_time + timedelta(
                seconds=attack_index * (window_seconds + 1)
            )
            for attempt in range(attempts_per_attack):
                timestamp = sequence_start + timedelta(seconds=attempt * seconds_between_attempts)
                username = self.random.choice(user_values)
                port = self.random.randint(10000, 65535)
                pid = self.random.randint(1000, 9999) + attempt
                if scenario == "successful-login":
                    message = f"Accepted password for {username} from {source_ip} port {port} ssh2"
                elif scenario == "preauth-scan":
                    message = f"Bad protocol version identification from {source_ip} port {port}"
                else:
                    pattern = self.random.choice(FAILURE_PATTERNS)
                    message = pattern.format(user=username, ip=source_ip, port=port)
                result.append(self._format_entry(timestamp, hostname, pid, message))
        return result

    def write_attacks_to_file(
        self,
        num_attacks: int = 1,
        attempts_per_attack: int = 5,
        **options: object,
    ) -> int:
        """Create a private output file once; never append to or overwrite files."""
        entries = self.generate_entries(
            num_attacks=num_attacks,
            attempts_per_attack=attempts_per_attack,
            **options,
        )
        output = _validate_output(self.log_file)
        parent = output.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError(f"Output directory is not a real directory: {parent}")
        parent_stat = parent.stat()
        if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise PermissionError(
                f"Output directory must be owned by this user and mode 0700: {parent}"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(output, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.writelines(f"{entry}\n" for entry in entries)
        return len(entries)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate local SSH log fixtures; this does not send network traffic."
    )
    parser.add_argument("--log-file", "--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--num-attacks", type=int, default=1)
    parser.add_argument("--attempts-per-attack", type=int, default=5)
    parser.add_argument("--source-ip", action="append", dest="source_ips")
    parser.add_argument("--username", action="append", dest="usernames")
    parser.add_argument(
        "--scenario",
        choices=("brute-force", "successful-login", "preauth-scan"),
        default="brute-force",
    )
    parser.add_argument("--window-seconds", type=float, default=120)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--print-only", action="store_true", help="Write records only to stdout")
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Label output as local test data; no traffic is sent",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        simulator = AttackSimulator(args.log_file, seed=args.seed)
        if args.print_only:
            entries = simulator.generate_entries(
                num_attacks=args.num_attacks,
                attempts_per_attack=args.attempts_per_attack,
                source_ips=args.source_ips,
                usernames=args.usernames,
                scenario=args.scenario,
                window_seconds=args.window_seconds,
            )
            for entry in entries:
                print(entry)
            return 0
        count = simulator.write_attacks_to_file(
            num_attacks=args.num_attacks,
            attempts_per_attack=args.attempts_per_attack,
            source_ips=args.source_ips,
            usernames=args.usernames,
            scenario=args.scenario,
            window_seconds=args.window_seconds,
        )
        mode = "TEST MODE: " if args.test_mode else ""
        print(f"{mode}Wrote {count} local simulated records to {simulator.log_file}")
        print("No network traffic was sent.")
        return 0
    except (OSError, ValueError) as error:
        print(f"Simulator error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
