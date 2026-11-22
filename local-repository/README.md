# Local Content-Addressed Repository Template (`local-repository/`)

Self-contained Python 3.11+ adapter publishing immutable content-addressed blobs (`<sha256>.bin`) and atomically swapping `<sha256(projectId)>/current.json`, with checksum-verified `AUTHORITATIVE` destination inventory.

Requires only the Python standard library and Linux `flock`. Copy this entire folder to `/opt/publishd/local-repository/` with zero external files required.

## Source & Destination Layout

Source artifacts:

```text
<artifactRoot>/
  <sha256(projectId UTF-8)>/
    <sha256(version UTF-8)>/
      <candidate-name>/
        metadata.json   # exact {"projectId": "...", "version": "..."}
        payload.bin
```

Published destination:

```text
<root>/
  <sha256(projectId UTF-8)>/
    <sha256(payload.bin)>.bin
    current.json        # {"projectId": "...", "version": "...", "sha256": "..."}
```

## Quick Validation

```sh
../tools/check-abi.py publish --option-id 00000000-0000-0000-0000-000000000028 \
  --server-id test --channel-id candidate --project-id sample-project --version 2:4.1~rc1 \
  --probe-negative-inputs \
  -- /usr/bin/python3 -I ./publish.py --config /var/lib/publishd/local/config.json

../tools/check-abi.py inventory --purpose VERIFY --require-authoritative \
  --option-id 00000000-0000-0000-0000-000000000028 \
  --server-id test --channel-id candidate --project-id sample-project \
  --probe-negative-inputs \
  -- /usr/bin/python3 -I ./inventory.py --config /var/lib/publishd/local/config.json
```
