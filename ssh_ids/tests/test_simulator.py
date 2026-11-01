import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ssh_ids.src.parser import SSHLogParser
from ssh_ids.tests.simulate_attacks import (
    DEFAULT_OUTPUT,
    MAX_SIMULATED_RECORDS,
    AttackSimulator,
    is_protected_auth_log,
    main,
)

START = datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_default_simulator_destination_is_private_test_file():
    assert DEFAULT_OUTPUT == Path(tempfile.gettempdir()) / "ssh-ids-test" / "auth_simulation.log"
    assert not is_protected_auth_log(DEFAULT_OUTPUT)
    assert AttackSimulator().log_file == DEFAULT_OUTPUT


@pytest.mark.parametrize(
    "path",
    ["/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1", "/var/log/secure-2024"],
)
def test_protected_system_auth_logs_are_rejected(path):
    assert is_protected_auth_log(path)
    with pytest.raises(ValueError, match="protected authentication log"):
        AttackSimulator(path)


def test_symlink_alias_to_protected_auth_log_is_rejected(tmp_path):
    alias = tmp_path / "auth-alias"
    alias.symlink_to("/var/log/auth.log")
    assert is_protected_auth_log(alias)
    with pytest.raises(ValueError, match="protected authentication log"):
        AttackSimulator(alias)


def test_simulator_writes_private_file_once_and_never_overwrites(tmp_path):
    output = tmp_path / "private" / "simulation.log"
    simulator = AttackSimulator(output, seed=7, start_time=START)
    assert simulator.write_attacks_to_file(attempts_per_attack=2) == 2
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.read_text(encoding="utf-8").count("\n") == 2
    with pytest.raises(FileExistsError):
        simulator.write_attacks_to_file(attempts_per_attack=1)
    assert output.read_text(encoding="utf-8").count("\n") == 2


def test_simulator_records_are_valid_chronological_and_seed_deterministic():
    first = AttackSimulator(seed=99, start_time=START).generate_entries(
        num_attacks=2,
        attempts_per_attack=5,
        source_ips=["192.0.2.90"],
        usernames=["root"],
    )
    second = AttackSimulator(seed=99, start_time=START).generate_entries(
        num_attacks=2,
        attempts_per_attack=5,
        source_ips=["192.0.2.90"],
        usernames=["root"],
    )
    assert first == second
    parsed = [SSHLogParser().parse_line(record) for record in first]
    assert all(entry is not None for entry in parsed)
    times = [entry.timestamp for entry in parsed if entry is not None]
    assert times == sorted(times)
    assert max(times[:5]) - min(times[:5]) < __import__("datetime").timedelta(minutes=2)
    assert {entry.source_ip for entry in parsed if entry is not None} == {"192.0.2.90"}


def test_seed_alone_produces_repeatable_records_within_the_same_year():
    assert AttackSimulator(seed=99).generate_entries(attempts_per_attack=3) == (
        AttackSimulator(seed=99).generate_entries(attempts_per_attack=3)
    )


@pytest.mark.parametrize("scenario", ["successful-login", "preauth-scan"])
def test_non_bruteforce_scenarios_are_classified_as_non_failures(scenario):
    records = AttackSimulator(seed=5, start_time=START).generate_entries(
        attempts_per_attack=1, scenario=scenario
    )
    entry = SSHLogParser().parse_line(records[0])
    assert entry is not None
    assert not entry.is_failure


def test_simulator_validation_rejects_bad_options_and_ips(tmp_path):
    simulator = AttackSimulator(tmp_path / "out.log", start_time=START)
    with pytest.raises(ValueError, match="positive"):
        simulator.generate_entries(attempts_per_attack=0)
    with pytest.raises(ValueError, match="source IP"):
        simulator.generate_entries(source_ips=["300.1.1.1"])
    with pytest.raises(ValueError, match="scenario"):
        simulator.generate_entries(scenario="unknown")
    with pytest.raises(ValueError, match="window_seconds"):
        simulator.generate_entries(window_seconds=float("inf"))
    with pytest.raises(ValueError, match="record count"):
        simulator.generate_entries(num_attacks=MAX_SIMULATED_RECORDS + 1)
    with pytest.raises(ValueError, match="hostname"):
        simulator.generate_entries(hostname="host\nforged")
    with pytest.raises(ValueError, match="Usernames"):
        simulator.generate_entries(usernames=["root\x00"])
    with pytest.raises(ValueError, match="timezone-aware"):
        AttackSimulator(tmp_path / "naive.log", start_time=datetime(2024, 1, 1))


def test_simulator_refuses_unrelated_symlink_destination(tmp_path):
    target = tmp_path / "unrelated.txt"
    link = tmp_path / "output.log"
    target.write_text("keep this file", encoding="utf-8")
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        AttackSimulator(link)
    assert target.read_text(encoding="utf-8") == "keep this file"


def test_print_only_never_creates_output_file(tmp_path, capsys):
    output = tmp_path / "print-only.log"
    status = main(["--log-file", str(output), "--print-only", "--seed", "5"])
    assert status == 0
    assert not output.exists()
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 5
    assert "Failed " in lines[0] or "Invalid user" in lines[0]


def test_test_mode_writes_only_explicit_local_destination(tmp_path, capsys):
    output = tmp_path / "safe-test.log"
    status = main(
        [
            "--test-mode",
            "--log-file",
            str(output),
            "--seed",
            "5",
            "--attempts-per-attack",
            "2",
        ]
    )
    assert status == 0
    assert output.exists()
    assert "TEST MODE" in capsys.readouterr().out
    assert not is_protected_auth_log(output)


def test_simulator_script_runs_outside_repository_cwd(tmp_path):
    import subprocess
    import sys

    script = Path(__file__).with_name("simulate_attacks.py")
    result = subprocess.run(
        [sys.executable, str(script), "--print-only", "--seed", "3", "--attempts-per-attack", "1"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "sshd[" in result.stdout
    assert result.stderr == ""
