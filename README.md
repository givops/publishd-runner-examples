# GivOps `publishd-runner-examples`

Self-contained, copy-paste Python 3.11+ starter templates, Script ABI v1 specification, standalone contract validator, and offline Docker verification suite for [`publishd-runner`](https://givops.io/publishd-runner/).

The Java 25 / Spring Boot `publishd-runner` execution service remains private, while these script templates and tooling are published under the [MIT License](LICENSE) so operators can copy, adapt, and vendor any template folder directly into private infrastructure repositories.

## Starter templates

Every template directory is **self-contained** (no shared parent-directory imports or external `pip` dependencies):

| Directory | Purpose | Transport & Promotion | Verification Source | Runtime Requirements |
| --- | --- | --- | --- | --- |
| [`minimal-template/`](minimal-template/) | Heavily commented skeleton scripts with explicit customization markers | Local staging + atomic `os.replace` | Direct `release.json` + SHA-256 blob read | Python 3.11+ stdlib, Linux `flock` |
| [`local-repository/`](local-repository/) | Reference local content-addressed repository adapter | `fsync` blob + atomic `current.json` swap | Direct `current.json` + SHA-256 blob read | Python 3.11+ stdlib, Linux `flock` |
| [`ftps/`](ftps/) | Explicit FTPS upload and remote verification adapter | `FTP_TLS` + `PROT P` + `TYPE I`, `.part` upload + `RNFR`/`RNTO` rename | Direct remote FTPS `current.json` + SHA-256 `RETR` read | Python 3.11+ stdlib, Linux `flock`, mode-`0600` `.netrc` |
| [`rsync-ssh/`](rsync-ssh/) | Two-host repository promotion over OpenSSH and `rsync` | `rsync` to staging + SSH remote `receive.py` finalizer | Remote SSH execution of `inventory.py` on target host | Python 3.11+ stdlib, Linux `flock`, `openssh-client`, `rsync` |
| [`apt/`](apt/) | Local or remote-SSH Debian `reprepro` package publishing | Local `reprepro` or `rsync` + SSH `receive.py` | Direct `Release` SHA-256 + `Packages` + `pool/*.deb` `dpkg-deb` audit | Python 3.11+ stdlib, Linux `flock`, `dpkg-deb`, `reprepro` (+ `openssh-client`, `rsync` in SSH mode) |

## Quick copy-paste workflow

1. Copy a single template folder (for example `ftps/` or `minimal-template/`) into your private infrastructure repository or `/opt/publishd/<my-target>/`:

   ```sh
   cp -r ftps /opt/publishd/my-ftps-target
   ```

2. Copy the example configuration files (`config.example.json`, `runner-profile.example.yaml`, and `netrc.example` or `ssh-config.example` if used), replace placeholder paths, UUIDs, and `.example.invalid` hostnames, and lock down secret files to mode `0600`:

   ```sh
   install -m 0600 ftps/netrc.example /etc/publishd/ftps.netrc
   ```

3. Validate your customized `publish.py` and `inventory.py` locally against Script ABI v1 **without needing the private `publishd-runner` binary**:

   ```sh
   ./tools/check-abi.py publish \
     --option-id 00000000-0000-0000-0000-000000000028 \
     --server-id edge --channel-id stable \
     --project-id sample-project --version 1.2.3 \
     --probe-negative-inputs \
     -- /usr/bin/python3 -I /opt/publishd/my-ftps-target/publish.py --config /etc/publishd/my-target.json

   ./tools/check-abi.py inventory \
     --purpose VERIFY --require-authoritative \
     --option-id 00000000-0000-0000-0000-000000000028 \
     --server-id edge --channel-id stable \
     --project-id sample-project \
     --probe-negative-inputs \
     -- /usr/bin/python3 -I /opt/publishd/my-ftps-target/inventory.py --config /etc/publishd/my-target.json
   ```

4. Register the fixed interpreter, script path, working directory, environment, and `resourceGroup` in your `publishd-runner` profile configuration (see each folder's `runner-profile.example.yaml` and [`PROTOCOL.md`](PROTOCOL.md)).

## Documentation & tooling

- [`PROTOCOL.md`](PROTOCOL.md) — Complete Script ABI v1 specification: process supervision (`setsid`), JSON stdin/stdout schemas, size and timeout ceilings, locking, journaling, outcome semantics, and safe error codes.
- [`tools/check-abi.py`](tools/check-abi.py) — Standalone Script ABI v1 validator CLI for scripts written in any language (Python, Bash, Go, Rust, etc.).

## Offline verification

Run the complete disposable verification suite in an isolated Linux container (`--network none`, non-root user `65532:65532`, loopback OpenSSH, loopback Explicit FTPS with generated test CA, and real `dpkg-deb` / `reprepro` repositories):

```sh
./scripts/verify-local.sh
```

The test suite copies each template folder to a standalone temporary directory outside the repository tree before invoking it with `python3 -I`, verifying that every folder operates independently.

## License and trademarks

All code, example configurations, validator tooling, and documentation in this repository are licensed under the [MIT License](LICENSE).

**Trademark notice:** The **GivOps** name and logo are trademarks of GivOps and are **not** licensed under the MIT License.
