# Explicit FTPS Delivery & Inventory Template (`ftps/`)

Self-contained Python 3.11+ adapter using Python's standard-library `ftplib.FTP_TLS` for explicit FTPS (`AUTH TLS`, `PBSZ 0`, `PROT P`, binary `TYPE I`) with strict TLS certificate verification, mode-`0600` external `netrc` credentials, advisory `flock` locking, pre-mutation operation journaling, `.part` staging upload + atomic `RNFR`/`RNTO` rename, and direct live FTPS `AUTHORITATIVE` inventory.

Copy this entire folder directly to `/opt/publishd/ftps/` — zero parent imports or `pip` packages are needed.

## Security & Reliability Guarantees

- **Strict credential custody (`netrc`)**: Credentials live in a dedicated external file (see `netrc.example`), never inline in JSON config. Both `publish.py` and `inventory.py` refuse to connect unless the `netrcFile` is a non-symlink regular file owned by the invoking user with exact mode `0600`.
- **Verified explicit TLS**: Connects over explicit `AUTH TLS` (`TLSv1.2+`), enforces hostname verification and CA verification against `caFile` (or system roots when omitted), and protects every data connection with `PROT P` and binary `TYPE I`.
- **Zero mutation on rejection**: Artifact validation (`ARTIFACT_UNAVAILABLE`, `ARTIFACT_AMBIGUOUS`, `ARTIFACT_REJECTED`), allowlist validation (`DESTINATION_REJECTED`), and `netrc`/TLS config checks run before creating a started journal or opening any network socket.
- **No blind replay on uncertainty**: The operation journal is `fsync`ed before the FTPS transfer begins. Any interrupted upload, TLS error, or failed `RNFR`/`RNTO` transitions to `UNKNOWN` (`PUBLICATION_UNCERTAIN`) and refuses automatic replay on retry.
- **Atomic staging**: Payloads upload to `.payload-<sha256(operationId)>.part` and promote via `RNFR`/`RNTO` to `<sha256>.bin`, followed by `.current-<sha256(operationId)>.part` -> `current.json`.
- **Authoritative live inventory**: `inventory.py` connects directly to the FTPS server, reads `current.json`, downloads `<sha256>.bin`, and verifies byte length and SHA-256 digest without consulting `artifactRoot` or `journalRoot`.

## Provisioning

```sh
install -d -m 0750 /etc/publishd
install -m 0600 ftps/netrc.example /etc/publishd/ftps.netrc
install -m 0600 ftps/config.example.json /etc/publishd/ftps-config.json
# Install your trusted CA bundle at /etc/publishd/ftps-ca.pem and edit host/credentials.
```

## Quick Validation

```sh
../tools/check-abi.py publish \
  --option-id 00000000-0000-0000-0000-000000000028 \
  --server-id edge --channel-id stable \
  --project-id sample-project --version 1.2.3 \
  --probe-negative-inputs \
  -- /usr/bin/python3 -I ./publish.py --config /etc/publishd/ftps-config.json

../tools/check-abi.py inventory \
  --purpose VERIFY --require-authoritative \
  --option-id 00000000-0000-0000-0000-000000000028 \
  --server-id edge --channel-id stable \
  --project-id sample-project \
  --probe-negative-inputs \
  -- /usr/bin/python3 -I ./inventory.py --config /etc/publishd/ftps-config.json
```
