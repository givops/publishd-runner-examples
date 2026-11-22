# Minimal Starter Template (`minimal-template/`)

A standalone, single-file-per-entrypoint Python 3.11+ skeleton implementing `publishd-runner` Script ABI v1 with zero dependencies beyond the Python standard library and Linux `flock`.

Copy this directory directly to `/opt/publishd/my-target/` and customize only the marked `# === CUSTOMIZE STEP ... ===` sections in `publish.py` and `inventory.py`.

## Files

- `publish.py`: Complete, heavily commented publication skeleton with strict ABI parsing, destination allowlist checks, advisory `flock`, pre-mutation `fsync` operation journaling, and atomic promotion.
- `inventory.py`: Complete, heavily commented inventory skeleton enforcing independent live destination verification (`AUTHORITATIVE` mode).
- `config.example.json`: Private configuration file (install mode `0600`).
- `runner-profile.example.yaml`: Matching `publishd-runner` profile configuration snippet.

## Quick test after customizing

```sh
../tools/check-abi.py publish \
  --option-id 00000000-0000-0000-0000-000000000028 \
  --server-id production --channel-id stable \
  --project-id sample-project --version 1.0.0 \
  --probe-negative-inputs \
  -- /usr/bin/python3 -I ./publish.py --config /etc/publishd/my-target.json

../tools/check-abi.py inventory \
  --purpose VERIFY --require-authoritative \
  --option-id 00000000-0000-0000-0000-000000000028 \
  --server-id production --channel-id stable \
  --project-id sample-project \
  --probe-negative-inputs \
  -- /usr/bin/python3 -I ./inventory.py --config /etc/publishd/my-target.json
```
