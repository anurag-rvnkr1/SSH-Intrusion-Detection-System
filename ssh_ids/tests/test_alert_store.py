import json
import stat

import pytest

from ssh_ids.src.alert_store import LocalAlertStore


def test_store_appends_json_lines_to_private_file(tmp_path):
    output = tmp_path / "alerts.jsonl"
    store = LocalAlertStore(output)
    store.append({"alert_id": "a1", "attempts": 5})
    store.append({"alert_id": "a2", "attempts": 6})
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert rows == [
        {"alert_id": "a1", "attempts": 5},
        {"alert_id": "a2", "attempts": 6},
    ]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_alert_records_survive_store_recreation(tmp_path):
    output = tmp_path / "alerts.jsonl"
    LocalAlertStore(output).append({"alert_id": "before-restart"})
    LocalAlertStore(output).append({"alert_id": "after-restart"})
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["alert_id"] for row in rows] == ["before-restart", "after-restart"]


def test_store_rejects_protected_paths_and_symlink_files(tmp_path):
    with pytest.raises(ValueError, match="system authentication log"):
        LocalAlertStore("/var/log/auth.log")
    link = tmp_path / "link.jsonl"
    link.symlink_to(tmp_path / "target.jsonl")
    with pytest.raises(ValueError, match="must not be a symlink"):
        LocalAlertStore(link)


def test_store_rejects_insecure_existing_file(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text("", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(PermissionError, match="private regular file"):
        LocalAlertStore(path).append({"alert_id": "a"})


def test_store_rejects_shared_output_directory(tmp_path):
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)
    with pytest.raises(PermissionError, match="private and user-owned"):
        LocalAlertStore(directory / "alerts.jsonl").append({"alert_id": "a"})


def test_store_rejects_non_json_alert_values(tmp_path):
    with pytest.raises(ValueError, match="JSON compliant"):
        LocalAlertStore(tmp_path / "alerts.jsonl").append({"invalid": float("nan")})
