"""Permission-restricted append-only local JSONL alert storage."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .utils import is_protected_auth_log


class LocalAlertStore:
    """Append validated JSON alert records without following file symlinks."""

    def __init__(self, path: str | Path):
        requested = Path(path).expanduser()
        if requested.is_symlink():
            raise ValueError(f"Local alert file must not be a symlink: {requested}")
        self.path = requested.resolve(strict=False)
        if is_protected_auth_log(self.path):
            raise ValueError("Local alert file cannot be a system authentication log")

    def append(self, alert: dict[str, Any]) -> None:
        """Append one JSON record to a private, user-owned file."""
        encoded = (
            json.dumps(alert, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode("utf-8")
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_stat = parent.stat()
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) & 0o077
        ):
            raise PermissionError(f"Alert directory must be private and user-owned: {parent}")

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.getuid()
                or stat.S_IMODE(file_stat.st_mode) & 0o077
            ):
                raise PermissionError(
                    f"Alert file must be a private regular file owned by this user: {self.path}"
                )
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
