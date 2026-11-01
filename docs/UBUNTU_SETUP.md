# Ubuntu setup and real-log monitoring

## Install

On Ubuntu 24.04, install the system Python and virtual-environment packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/anurag-rvnkr1/SSH-Intrusion-Detection-System.git
cd SSH-Intrusion-Detection-System
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Runtime code uses the Python standard library. Development requirements install
pytest/coverage, Ruff, mypy, and Bandit. No service is installed and no system
log is modified by setup.

## Configure and run

Review `ssh_ids/config/config.json`. The checked-in configuration lists
`/var/log/auth.log` and `/var/log/secure`; one may not exist on a given host.
Set `polling.log_files` to the actual readable authentication log(s), and
choose whether to process pre-existing records (`initial_read: beginning`) or
only new records (`initial_read: end`).

Run from the repository root:

```bash
python3 -m ssh_ids.src.main --config ssh_ids/config/config.json
```

The normal application reads logs; it does not write or change their
permissions. The simulator is a separate tool and must never target those
paths. Use the isolated [demo walkthrough](./DEMO_WALKTHROUGH.md) first.

## Least-privilege log access

Do not run the whole detector as root and do not make authentication logs
world-readable. Inspect local ownership and access policy without changing it:

```bash
stat -c '%A %U:%G %n' /var/log/auth.log
id
getent group adm
```

On many Ubuntu installations, `adm` can read selected system logs. Membership
in that group is a privileged host-policy decision and may expose more than
authentication records. Ask the host administrator to approve the narrowest
available read-only mechanism; do not change file modes or ownership just to
make the demo work. If the account is authorized for the existing log-reader
group, group membership changes require signing out and back in to take effect.

The application currently monitors files, not journald directly. Configure
only files available to the chosen account. Missing files are reported and
retried; permission errors are logged without escalating privileges.

## Environment variables

For enabled integrations, set secrets in the process environment, for example:

```bash
read -rsp 'Splunk HEC token: ' SPLUNK_HEC_TOKEN
export SPLUNK_HEC_TOKEN
printf '\n'
```

The loader expands `${SPLUNK_HEC_TOKEN}` from JSON but does not auto-load a
`.env` file. Never commit actual credentials.
