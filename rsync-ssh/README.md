# Staged Repository Promotion over OpenSSH & `rsync` (`rsync-ssh/`)

Self-contained Python 3.11+ adapter for two-host repository delivery using OpenSSH batch authentication, strict host-key verification, `rsync --protect-args`, destination-side advisory `flock` + journaling (`receive.py`), and direct remote `AUTHORITATIVE` verification (`inventory.py`).

Copy this entire `rsync-ssh/` directory directly to `/opt/publishd/rsync-ssh/` on **both** the runner host and the repository host — zero sibling folders or `pip` packages are needed.

## Host Roles

- **Runner host (`publish.py`, `inventory.py`, `config.example.json`, `ssh-config.example`)**:
  1. Validates destination allowlist and local artifact before any network transfer (`REJECTED` guarantees zero remote transfer).
  2. Writes and `fsync`s the sender journal under local `resourceLock`.
  3. Transfers only the validated candidate into `<ssh.stagingRoot>/<sha256(operationId)>/` via `rsync`.
  4. Invokes remote `receive.py` over SSH with request JSON on stdin (opaque strings never enter shell commands).
  5. Any transfer, host-key, or remote error after staging begins returns `UNKNOWN` / `PUBLICATION_UNCERTAIN` and never replays.

- **Repository host (`receive.py`, `inventory.py`, `remote-config.example.json`)**:
  1. `receive.py` acquires the repository `resourceLock`, verifies the staged candidate, deduplicates via the repository journal, writes & `fsync`s `<sha256>.bin`, and atomically swaps `current.json`.
  2. `inventory.py` (when invoked with `remote-config.json`, which has `"root"` and no `"ssh"` block) reads `current.json` and verifies `<sha256>.bin` SHA-256 bytes directly on the repository host.

## Provisioning

On the repository host:

```sh
install -d -m 0700 /srv/publishd/rsync-repository/staging
install -d -m 0755 /srv/publishd/rsync-repository/repository
install -d -m 0750 /srv/publishd/rsync-repository/journal
install -m 0600 rsync-ssh/remote-config.example.json /srv/publishd/rsync-repository/private-config.json
```

On the runner host:

```sh
install -d -m 0700 /etc/publishd/ssh
install -m 0600 rsync-ssh/ssh-config.example /etc/publishd/ssh/config
install -m 0600 rsync-ssh/config.example.json /etc/publishd/rsync-ssh.json
# Provision a dedicated SSH identity key and pinned known_hosts (StrictHostKeyChecking yes).
```
