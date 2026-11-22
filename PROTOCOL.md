# `publishd-runner` Script ABI v1 Specification

This document defines the exact JSON stdin/stdout contract, process supervision model, locking/journaling requirements, and resource limits enforced by `publishd-runner`.

## 1. Execution & Process-Group Rules

`publishd-runner` invokes operator scripts directly on Linux without invoking a shell (`execve` via `ProcessBuilder`):

```text
/usr/bin/setsid -- <executable> <arguments...>
```

- **Fixed runtime configuration**: `executable`, `arguments`, `working-directory`, and `environment` come solely from the runner's trusted profile configuration (`publishd.profiles.<profileKey>.{publish,inventory}`). HTTP callers never supply paths, arguments, URLs, or environment variables.
- **Cleared environment**: the script environment is cleared before applying only the explicit key/value map declared in the profile. Scripts that run external CLI tools (such as `ssh`, `rsync`, `reprepro`, `dpkg-deb`) should ensure `PATH` (or absolute tool paths) and locale (`LANG=C.UTF-8` / `LC_ALL=C`) are handled cleanly.
- **Synchronous `setsid` rule**: the script executes in a new session and process group whose PGID equals its PID. When the script exits `0`, `publishd-runner` immediately checks `/bin/kill -0 -- -<pid>`.
  - **No background daemons or detached workers**: if any child process remains alive in the process group after exit `0`, `publishd-runner` kills the process group (`-KILL`) and classifies the job as `UNKNOWN` / `PUBLICATION_UNCERTAIN`.
  - On timeout or output overflow, `publishd-runner` kills the entire process group (`-KILL`).

## 2. Resource Locking & Operation Journaling

### Runner-side coordination

- Every server/channel target maps to a `resourceGroup` in the runner profile. PostgreSQL holds exclusive reservations across the entire publication lifecycle: baseline check -> callback permit -> `publish` invocation -> `VERIFY` inventory -> explicit operator resolution if `UNKNOWN`.
- Scripts must never attempt to override or bypass runner reservations.

### Script-side `flock` advisory locking

- All scripts sharing a physical destination repository should acquire an exclusive advisory `flock` (`LOCK_EX`) on a configured `resourceLock` file path using open mode `a+b` (never unlinking or replacing the lock file inode).
- Any out-of-band repository writers on the same host must acquire the same `resourceLock` inode.

### Pre-mutation operation journaling (`publish` only)

Before opening a remote connection or modifying destination state:

1. Validate the destination binding `(optionId, serverId, channelId)` against the private allowlist (`DESTINATION_REJECTED` on mismatch).
2. Validate all local inputs, credentials, and source artifacts (`ARTIFACT_*` on failure). Never write a started journal before local validation passes.
3. Persist an `fsync`ed journal record keyed by `sha256(operationId)` containing the SHA-256 fingerprint of the canonical request JSON:
   - If a journal entry already exists with a **different** request fingerprint: return `outcome: "REJECTED"`, `errorCode: "OPERATION_CONFLICT"`.
   - If a completed journal entry exists with the **same** fingerprint: return the stored response without mutating the destination again.
   - If a **started-without-result** journal entry exists (from an earlier crash, kill, or timeout): return `outcome: "UNKNOWN"`, `errorCode: "PUBLICATION_UNCERTAIN"`. **Never auto-replay a started transfer.**
4. Execute the destination transfer/promotion (prefer staging `.part` files + atomic `os.replace` or FTP `RNFR`/`RNTO`).
5. Record the final outcome in the journal (`fsync` + atomic replace). Any unexpected failure during or after step 4 must persist and return `outcome: "UNKNOWN"`, `errorCode: "PUBLICATION_UNCERTAIN"`.

## 3. Hard Size, Count & Timeout Ceilings

Values below reflect `publishd.limits` defaults and hard upper bounds:

| Limit | Default | Hard Maximum | Notes |
| --- | --- | --- | --- |
| Stdin request JSON | — | `4 MiB` (`4,194,304` bytes) | UTF-8 JSON |
| Stdout response JSON | `4 MiB` | `4 MiB` (`4,194,304` bytes) | Exceeding triggers `OUTPUT_LIMIT_EXCEEDED` |
| Stderr diagnostic stream | `256 KiB` | `256 KiB` (`262,144` bytes) | Drained & discarded; never returned in API responses |
| `publish` timeout | `5 minutes` | `15 minutes` | Positive duration; timeout triggers `PROCESS_TIMEOUT` |
| `inventory` timeout | `60 seconds` | `5 minutes` | Per target; timeout triggers `PROCESS_TIMEOUT` |
| `projectIds` / `deployments` count | `20,000` | `20,000` | Checked alongside the `4 MiB` byte limit |
| Configured server/channel pairs | `100` | `100` | Per runner profile |

## 4. Common JSON Rules

`publishd-runner` parses both stdin and stdout using strict Jackson rules (`STRICT_DUPLICATE_DETECTION`, `FAIL_ON_TRAILING_TOKENS`):

- **Single UTF-8 JSON object** on stdout; no leading/trailing text, comments, or second JSON document.
- **No duplicate keys** anywhere in any JSON object.
- **No unknown or missing fields**: every object schema below has an exact closed set of keys.
- **Strict primitive types**:
  - `abiVersion` must be an integral JSON number equal to `1` (note: in Python, `isinstance(True, int)` is `True`, so validate `type(value) is int`).
  - Booleans (`complete`, `sourceStale`) must be JSON `true` or `false`.
- **String rules**:
  - Strings must be non-blank (contain at least one non-whitespace character) and free of ISO control characters (`U+0000..U+001F`, `U+007F..U+009F`) and unpaired UTF-16 surrogates (`U+D800..U+DFFF`).
  - `operationId` and `optionId`: canonical lowercase 36-character UUID (`8-4-4-4-12`).
  - `serverId` and `channelId`: `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` (max 128 characters).
  - `projectId`: opaque non-blank string, max 255 characters. Treat as untrusted data; never interpolate into shell commands or unhashed filesystem paths.
  - `version`: opaque non-blank string, max 1024 characters. Preserve epochs, tilde pre-releases, and trailing zeros verbatim. Never apply fuzzy matching or package-version equivalence.

## 5. `publish` Contract

### Request (stdin)

```json
{
  "abiVersion": 1,
  "operation": "publish",
  "operationId": "11111111-1111-4111-8111-111111111111",
  "optionId": "00000000-0000-0000-0000-000000000028",
  "serverId": "edge",
  "channelId": "stable",
  "projectId": "sample-project",
  "version": "2:4.1~rc1"
}
```

### Response (stdout, exit code `0`)

```json
{
  "abiVersion": 1,
  "operationId": "11111111-1111-4111-8111-111111111111",
  "outcome": "APPLIED"
}
```

Or with optional `errorCode` (required/recommended on `REJECTED` and `UNKNOWN`):

```json
{
  "abiVersion": 1,
  "operationId": "11111111-1111-4111-8111-111111111111",
  "outcome": "REJECTED",
  "errorCode": "ARTIFACT_UNAVAILABLE"
}
```

- Exact allowed keys: `abiVersion`, `operationId`, `outcome`, and optional `errorCode` (string <= 64 chars, or `null` / omitted).
- `operationId` must match the stdin `operationId`.
- Never log secrets, credentials, private paths, or raw tool diagnostics to stdout or stderr.

### Outcomes and guarantees

| Outcome | Meaning | Side-Effect Guarantee | Runner Follow-Up |
| --- | --- | --- | --- |
| `APPLIED` | Artifact transferred and promoted to destination | Destination now intended to serve `(projectId, version)` | Runner immediately runs `inventory` (`VERIFY`); requires fresh `AUTHORITATIVE` match before job `SUCCEEDED` |
| `ALREADY_PRESENT` | Destination already served exact `(projectId, version)` and valid checksum | No new transfer/mutation performed | Runner still runs `inventory` (`VERIFY`) before confirming `SUCCEEDED` |
| `REJECTED` | Input, destination binding, or local artifact validation failed | **Zero destination mutation.** No remote write occurred | Runner transitions job to `REJECTED` (`effect: NONE`) and releases lock |
| `UNKNOWN` | Failure, interruption, or ambiguity occurred after mutation could have started | Possible partial or complete remote mutation | Runner sets job to `UNKNOWN` (`effect: POSSIBLE`) and **retains the resource lock** until operator resolution |

### Safe script `errorCode` values

Only the six safe script error codes below map verbatim to runner job problem codes; any other code emitted by a script is normalized by `publishd-runner` to `SCRIPT_FAILED`:

| `errorCode` | Typical Outcome | Meaning |
| --- | --- | --- |
| `ARTIFACT_UNAVAILABLE` | `REJECTED` | Zero matching source artifacts found for exact `(projectId, version)` |
| `ARTIFACT_AMBIGUOUS` | `REJECTED` | Multiple matching candidate artifacts found for exact `(projectId, version)` |
| `ARTIFACT_REJECTED` | `REJECTED` | Candidate artifact failed integrity, symlink, schema, or metadata validation |
| `DESTINATION_REJECTED` | `REJECTED` | `(optionId, serverId, channelId)` is not present in private allowlist |
| `OPERATION_CONFLICT` | `REJECTED` | `operationId` already exists in journal with a different request payload |
| `PUBLICATION_UNCERTAIN` | `UNKNOWN` | Transfer/promotion interrupted, failed after start, or started journal cannot be replayed |

Non-zero exit codes or malformed stdout on `publish` fail closed (`SCRIPT_FAILED` if no mutation began; `UNKNOWN` once the runner started execution).

## 6. `inventory` Contract

### Request (stdin)

```json
{
  "abiVersion": 1,
  "operation": "inventory",
  "operationId": "22222222-2222-4222-8222-222222222222",
  "optionId": "00000000-0000-0000-0000-000000000028",
  "serverId": "edge",
  "channelId": "stable",
  "projectIds": ["project-a", "project-b"],
  "purpose": "VERIFY"
}
```

- `purpose`: `"REFRESH"` (full catalog refresh across all targets) or `"VERIFY"` (authoritative pre/post-publish or reconciliation verification for one target).
- `projectIds`: list of unique opaque project IDs (max `20,000`). Scripts must scope `deployments` strictly to this list.

### Response (stdout, exit code `0`)

```json
{
  "abiVersion": 1,
  "operationId": "22222222-2222-4222-8222-222222222222",
  "serverId": "edge",
  "channelId": "stable",
  "complete": true,
  "observationMode": "AUTHORITATIVE",
  "sourceObservedAt": null,
  "sourceStale": false,
  "deployments": [
    {
      "projectId": "project-a",
      "version": "2:4.1~rc1",
      "sourceObservedAt": null
    }
  ]
}
```

Exact rules enforced by `publishd-runner`:

- Root keys must be **exact**: `abiVersion`, `operationId`, `serverId`, `channelId`, `complete`, `observationMode`, `sourceObservedAt`, `sourceStale`, `deployments`.
- `operationId`, `serverId`, and `channelId` must match the stdin request.
- `complete` **must** be `true`. Incomplete or partial scans must exit non-zero (never emit `"complete": false` expecting partial import).
- `observationMode`:
  - `AUTHORITATIVE`: live direct read/revalidation of the actual destination under lock. **Required** for `VERIFY` to confirm publication, no-op, or `UNKNOWN` resolution.
  - `CACHED` or `UNKNOWN`: accepted during `REFRESH` (marks stored inventory `stale = true`), **never** accepted to verify a publication.
- `sourceObservedAt` (root and per-deployment): either `null` or a strict UTC ISO-8601 instant string ending with `Z` (e.g. `"2026-11-22T12:00:00Z"`, max 64 chars). Never fabricate invocation time as a source timestamp; emit `null` when the destination has no native publication timestamp.
- `sourceStale`: boolean (`false` for live authoritative reads).
- `deployments`: array (length <= `maxDeployments`, max `20,000`) of objects with **exact** keys `projectId`, `version`, `sourceObservedAt`:
  - Every `projectId` must appear in the stdin `projectIds` list and must appear **at most once**.
  - Absent projects are simply omitted (an empty `deployments: []` with `complete: true` and `observationMode: "AUTHORITATIVE"` authoritatively asserts nothing is currently deployed in scope).
  - Never consult `artifactRoot` or `journalRoot` when building inventory.
- On destination unavailability, corruption, or scope mismatch, exit non-zero with empty stdout and a single generic non-sensitive diagnostic line on stderr.
