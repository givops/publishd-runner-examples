# Debian `reprepro` APT Publishing Template (`apt/`)

Self-contained Python 3.11+ adapter for publishing validated `.deb` packages to a Debian `reprepro` repository either locally or on a remote repository host over OpenSSH + `rsync`, with `AUTHORITATIVE` `Release`/`Packages`/`pool` verification.

Copy this entire `apt/` folder directly to `/opt/publishd/apt/` (and to the repository host in SSH mode) — zero sibling folders or `pip` packages are needed.

## Safety & Identity Guarantees

- **Exact opaque version matching**: Package selection runs `/usr/bin/dpkg-deb --field <file> Package Version Architecture` and matches `Package` and `Version` strictly as strings (`1.0`, `1.00`, `1.0-0`, and `0:1.0` are distinct). Filenames are ignored.
- **No partial/corrupt repository tolerance**: Before publishing and on every inventory check, `Release` SHA-256 checksums, `Packages` size/digest, pool `.deb` checksums, and `dpkg-deb` metadata are re-verified under `flock`.
- **No silent downgrade or uncertain replay**: Any `reprepro` error after invocation starts (for example, failing `SignWith` after pool/DB insertion) is journaled and returned as `UNKNOWN` (`PUBLICATION_UNCERTAIN`), never `REJECTED`, and never auto-replayed.
- **SSH mode**: Transfers only the selected `.deb` as `artifact.deb` via `rsync --protect-args` to `<stagingRoot>/<sha256(operationId)>/` and runs `receive.py` on the repository host; repository signing keys remain strictly on the repository host.

## Provisioning

Initialize an empty `reprepro` repository using `distributions.example`:

```sh
install -d -m 0755 /var/lib/publishd/apt/repository/conf
cp apt/distributions.example /var/lib/publishd/apt/repository/conf/distributions
reprepro --basedir /var/lib/publishd/apt/repository export synthetic
install -m 0600 apt/config.example.json /etc/publishd/apt-config.json
```

For remote SSH mode, install `apt/config.ssh.example.json` + `apt/ssh-config.example` on the runner host and `apt/remote-config.example.json` on the repository host.
