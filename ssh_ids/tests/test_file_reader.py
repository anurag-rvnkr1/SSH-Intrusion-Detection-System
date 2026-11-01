from datetime import datetime, timezone

from ssh_ids.src.parser import LogFileReader


def record(second, ip="192.0.2.50"):
    timestamp = datetime(2024, 1, 1, 0, 0, second, tzinfo=timezone.utc).isoformat()
    return f"{timestamp} ubuntu sshd[1000]: Failed password for root from {ip} port 22 ssh2\n"


def test_reader_handles_missing_file_then_creation(tmp_path):
    path = tmp_path / "auth.log"
    reader = LogFileReader(path, initial_read="beginning")
    try:
        assert reader.read_new_lines() == []
        path.write_text(record(1), encoding="utf-8")
        assert len(reader.read_new_lines()) == 1
    finally:
        reader.close()


def test_reader_reads_append_only_once_and_waits_for_complete_lines(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(record(1), encoding="utf-8")
    reader = LogFileReader(path, initial_read="beginning")
    try:
        assert len(reader.read_new_lines()) == 1
        assert reader.read_new_lines() == []
        with path.open("a", encoding="utf-8") as handle:
            handle.write(record(2).rstrip("\n"))
        assert reader.read_new_lines() == []
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n")
        assert len(reader.read_new_lines()) == 1
    finally:
        reader.close()


def test_reader_detects_truncation_and_reads_rewritten_content(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(record(10), encoding="utf-8")
    reader = LogFileReader(path, initial_read="beginning")
    try:
        assert len(reader.read_new_lines()) == 1
        path.write_text(
            "2024-01-01T00:00:01+00:00 ubuntu sshd[1000]: Invalid user x from 1.1.1.1\n",
            encoding="utf-8",
        )
        entries = reader.read_new_lines()
        assert len(entries) == 1
        assert entries[0].source_ip == "1.1.1.1"
    finally:
        reader.close()


def test_reader_drains_old_inode_then_reads_rotated_path(tmp_path):
    path = tmp_path / "auth.log"
    rotated = tmp_path / "auth.log.1"
    path.write_text(record(1), encoding="utf-8")
    reader = LogFileReader(path, initial_read="beginning")
    try:
        assert len(reader.read_new_lines()) == 1
        with path.open("a", encoding="utf-8") as handle:
            handle.write(record(2))
        path.rename(rotated)
        path.write_text(record(3, "192.0.2.52"), encoding="utf-8")
        entries = reader.read_new_lines()
        assert len(entries) == 2
        assert entries[0].source_ip == "192.0.2.50"
        assert entries[1].source_ip == "192.0.2.52"
        assert reader.read_new_lines() == []
    finally:
        reader.close()


def test_reader_drains_large_old_inode_across_polls_and_flushes_final_record(tmp_path):
    path = tmp_path / "auth.log"
    rotated = tmp_path / "auth.log.1"
    path.write_text(record(1), encoding="utf-8")
    reader = LogFileReader(
        path, initial_read="beginning", max_bytes_per_poll=len(record(1).encode())
    )
    try:
        assert len(reader.read_new_lines()) == 1
        with path.open("a", encoding="utf-8") as handle:
            handle.write(record(2) + record(3).rstrip("\n"))
        path.rename(rotated)
        path.write_text(record(4, "192.0.2.52"), encoding="utf-8")
        first_batch = reader.read_new_lines()
        second_batch = reader.read_new_lines()
        assert [entry.timestamp.second for entry in first_batch] == [2]
        assert [entry.timestamp.second for entry in second_batch] == [3, 4]
    finally:
        reader.close()


def test_reader_initial_read_end_skips_existing_records(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(record(1), encoding="utf-8")
    reader = LogFileReader(path, initial_read="end")
    try:
        assert reader.read_new_lines() == []
        with path.open("a", encoding="utf-8") as handle:
            handle.write(record(2))
        assert len(reader.read_new_lines()) == 1
    finally:
        reader.close()


def test_reader_created_after_first_poll_reads_new_file_from_beginning(tmp_path):
    path = tmp_path / "created-later.log"
    reader = LogFileReader(path, initial_read="end")
    try:
        assert reader.read_new_lines() == []
        path.write_text(record(1), encoding="utf-8")
        entries = reader.read_new_lines()
        assert len(entries) == 1
        assert entries[0].source_ip == "192.0.2.50"
    finally:
        reader.close()


def test_reader_rejects_invalid_initial_read(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="initial_read"):
        LogFileReader(tmp_path / "auth.log", initial_read="invalid")


def test_reader_rejects_non_integer_read_limit(tmp_path):
    import pytest

    for read_limit in (1.5, 0, 16777217):
        with pytest.raises(ValueError, match="max_bytes_per_poll"):
            LogFileReader(tmp_path / "auth.log", max_bytes_per_poll=read_limit)


def test_reader_limits_bytes_per_poll_and_preserves_partial_record(tmp_path):
    path = tmp_path / "auth.log"
    first_record = record(1)
    second_record = record(2)
    path.write_text(first_record + second_record, encoding="utf-8")
    first_record_size = len(first_record.encode("utf-8"))
    reader = LogFileReader(path, initial_read="beginning", max_bytes_per_poll=first_record_size + 5)
    try:
        first_batch = reader.read_new_lines()
        assert [entry.timestamp.second for entry in first_batch] == [1]
        second_batch = reader.read_new_lines()
        assert [entry.timestamp.second for entry in second_batch] == [2]
    finally:
        reader.close()


def test_reader_skips_oversized_records_and_continues(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("x" * 9000 + "\n" + record(2), encoding="utf-8")
    reader = LogFileReader(path, initial_read="beginning")
    try:
        entries = reader.read_new_lines()
        assert [entry.timestamp.second for entry in entries] == [2]
    finally:
        reader.close()


def test_reader_reports_permission_errors_only_once(tmp_path, caplog):
    from unittest.mock import patch

    path = tmp_path / "auth.log"
    path.write_text(record(1), encoding="utf-8")
    reader = LogFileReader(path, initial_read="beginning")
    try:
        with patch("pathlib.Path.open", side_effect=PermissionError):
            assert reader.read_new_lines() == []
            assert reader.read_new_lines() == []
        errors = [record for record in caplog.records if "Permission denied" in record.message]
        assert len(errors) == 1
    finally:
        reader.close()


def test_reader_closes_file_if_stat_fails_during_open(tmp_path):
    from unittest.mock import MagicMock, patch

    path = tmp_path / "auth.log"
    path.write_text(record(1), encoding="utf-8")
    reader = LogFileReader(path, initial_read="beginning")
    handle = MagicMock()
    try:
        with (
            patch("pathlib.Path.open", return_value=handle),
            patch("os.fstat", side_effect=OSError("stat failed")),
        ):
            assert reader.read_new_lines() == []
        handle.close.assert_called_once()
    finally:
        reader.close()
