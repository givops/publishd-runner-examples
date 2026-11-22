#!/usr/bin/env python3
"""Standalone Script ABI v1 validator CLI for publishd-runner operator scripts.

Validates publish and inventory scripts written in any language against the
strict JSON stdin/stdout, process-group (setsid), size/timeout, and error-code
contracts of publishd-runner without requiring the private runner binary.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

MAX_STDOUT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_PROJECTS = 20000
MAX_PUBLISH_TIMEOUT = 900
MAX_INVENTORY_TIMEOUT = 300

OUTCOMES = frozenset({"APPLIED", "ALREADY_PRESENT", "REJECTED", "UNKNOWN"})
REJECTION_ERROR_CODES = frozenset({
    "ARTIFACT_UNAVAILABLE",
    "ARTIFACT_AMBIGUOUS",
    "ARTIFACT_REJECTED",
    "DESTINATION_REJECTED",
    "OPERATION_CONFLICT",
})
SAFE_SCRIPT_ERROR_CODES = REJECTION_ERROR_CODES | frozenset({"PUBLICATION_UNCERTAIN"})
OBSERVATION_MODES = frozenset({"AUTHORITATIVE", "CACHED", "UNKNOWN"})
KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


class ValidationError(Exception):
    """Raised when script execution or ABI v1 validation fails."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise ValidationError(f"Non-standard JSON constant not allowed: {token!r}")


def parse_strict_json_document(raw: bytes, label: str = "stdout") -> dict[str, object]:
    if not raw:
        raise ValidationError(f"Empty {label}; expected a single UTF-8 JSON object")
    if len(raw) > MAX_STDOUT_BYTES:
        raise ValidationError(f"{label} exceeded {MAX_STDOUT_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{label} is not valid UTF-8: {exc}") from exc

    stripped = text.lstrip(" \t\r\n")
    if not stripped:
        raise ValidationError(f"Whitespace-only {label}; expected a JSON object")

    decoder = json.JSONDecoder(
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )
    try:
        document, end_idx = decoder.raw_decode(stripped)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Malformed JSON in {label}: {exc}") from exc

    trailing = stripped[end_idx:].strip(" \t\r\n")
    if trailing:
        raise ValidationError(f"Trailing tokens after JSON root in {label}")
    if not isinstance(document, dict):
        raise ValidationError(f"Root JSON value in {label} must be an object")
    return document


def validate_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    if not value.strip():
        raise ValidationError(f"{name} must not be blank")
    if len(value) > maximum:
        raise ValidationError(f"{name} exceeds maximum length {maximum}")
    for ch in value:
        code = ord(ch)
        if code < 32 or 127 <= code <= 159 or 0xD800 <= code <= 0xDFFF:
            raise ValidationError(f"{name} contains disallowed control/surrogate character")
    return value


def validate_key(value: object, name: str) -> str:
    text = validate_text(value, name, 128)
    if not KEY_RE.fullmatch(text):
        raise ValidationError(f"{name} must match {KEY_RE.pattern}: {text!r}")
    return text


def validate_uuid(value: object, name: str) -> str:
    text = validate_text(value, name, 36)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise ValidationError(f"{name} must be a canonical UUID: {text!r}") from exc
    if str(parsed) != text:
        raise ValidationError(f"{name} must be lowercase canonical UUID: {text!r}")
    return text


def validate_instant(value: object, name: str) -> str | None:
    if value is None:
        return None
    text = validate_text(value, name, 64)
    if not text.endswith("Z"):
        raise ValidationError(f"{name} must be null or a UTC ISO-8601 instant ending in 'Z'")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError(f"{name} is not a valid ISO-8601 UTC timestamp: {text!r}") from exc
    return text


def validate_publish_result(raw: bytes, expected_operation_id: str,
                            expect_outcome: str | None = None,
                            expect_error_code: str | None = None) -> dict[str, object]:
    doc = parse_strict_json_document(raw)
    required = {"abiVersion", "operationId", "outcome"}
    allowed = required | {"errorCode"}
    extra = set(doc) - allowed
    missing = required - set(doc)
    if missing:
        raise ValidationError(f"Missing required publish response field(s): {sorted(missing)}")
    if extra:
        raise ValidationError(f"Unknown publish response field(s): {sorted(extra)}")

    if type(doc["abiVersion"]) is not int or doc["abiVersion"] != 1:
        raise ValidationError(f"abiVersion must be integer 1, got {doc['abiVersion']!r}")

    op_id = validate_uuid(doc["operationId"], "operationId")
    if op_id != expected_operation_id:
        raise ValidationError(f"operationId mismatch: expected {expected_operation_id}, got {op_id}")

    outcome = validate_text(doc["outcome"], "outcome", 32)
    if outcome not in OUTCOMES:
        raise ValidationError(f"Invalid outcome {outcome!r}; expected one of {sorted(OUTCOMES)}")

    raw_error = doc.get("errorCode")
    error_code: str | None = None
    if raw_error is not None:
        error_code = validate_text(raw_error, "errorCode", 64)
        if error_code not in SAFE_SCRIPT_ERROR_CODES:
            raise ValidationError(
                f"Unsafe or unknown errorCode {error_code!r}; allowed script codes are "
                f"{sorted(SAFE_SCRIPT_ERROR_CODES)}"
            )

    if outcome in {"APPLIED", "ALREADY_PRESENT"} and error_code is not None:
        raise ValidationError(f"Outcome {outcome} must not include errorCode {error_code!r}")
    if outcome == "UNKNOWN" and error_code is not None and error_code != "PUBLICATION_UNCERTAIN":
        raise ValidationError(
            f"Outcome UNKNOWN must use errorCode 'PUBLICATION_UNCERTAIN' (or null), got {error_code!r}"
        )
    if outcome == "REJECTED" and error_code is not None and error_code not in REJECTION_ERROR_CODES:
        raise ValidationError(
            f"Outcome REJECTED must use a rejection errorCode {sorted(REJECTION_ERROR_CODES)}, got {error_code!r}"
        )

    if expect_outcome is not None and outcome != expect_outcome:
        raise ValidationError(f"Expected outcome {expect_outcome!r}, got {outcome!r}")
    if expect_error_code is not None and error_code != expect_error_code:
        raise ValidationError(f"Expected errorCode {expect_error_code!r}, got {error_code!r}")
    return doc


def validate_inventory_result(raw: bytes, request: dict[str, object],
                              require_authoritative: bool = False) -> dict[str, object]:
    doc = parse_strict_json_document(raw)
    expected_keys = {
        "abiVersion",
        "operationId",
        "serverId",
        "channelId",
        "complete",
        "observationMode",
        "sourceObservedAt",
        "sourceStale",
        "deployments",
    }
    missing = expected_keys - set(doc)
    extra = set(doc) - expected_keys
    if missing:
        raise ValidationError(f"Missing required inventory response field(s): {sorted(missing)}")
    if extra:
        raise ValidationError(f"Unknown inventory response field(s): {sorted(extra)}")

    if type(doc["abiVersion"]) is not int or doc["abiVersion"] != 1:
        raise ValidationError(f"abiVersion must be integer 1, got {doc['abiVersion']!r}")

    op_id = validate_uuid(doc["operationId"], "operationId")
    if op_id != request["operationId"]:
        raise ValidationError(f"operationId mismatch: expected {request['operationId']}, got {op_id}")

    server_id = validate_key(doc["serverId"], "serverId")
    channel_id = validate_key(doc["channelId"], "channelId")
    if server_id != request["serverId"] or channel_id != request["channelId"]:
        raise ValidationError("serverId/channelId mismatch between request and response")

    if doc["complete"] is not True:
        raise ValidationError(f"complete must be boolean true, got {doc['complete']!r}")

    mode = validate_text(doc["observationMode"], "observationMode", 32)
    if mode not in OBSERVATION_MODES:
        raise ValidationError(f"Invalid observationMode {mode!r}; expected one of {sorted(OBSERVATION_MODES)}")

    validate_instant(doc["sourceObservedAt"], "sourceObservedAt")
    if type(doc["sourceStale"]) is not bool:
        raise ValidationError(f"sourceStale must be boolean, got {doc['sourceStale']!r}")

    if require_authoritative and (mode != "AUTHORITATIVE" or doc["sourceStale"] is not False):
        raise ValidationError(
            f"Expected AUTHORITATIVE non-stale observation, got mode={mode!r}, sourceStale={doc['sourceStale']!r}"
        )

    deployments = doc["deployments"]
    if not isinstance(deployments, list):
        raise ValidationError("deployments must be a JSON array")
    if len(deployments) > MAX_PROJECTS:
        raise ValidationError(f"deployments count {len(deployments)} exceeds maximum {MAX_PROJECTS}")

    allowed_projects = set(request["projectIds"])  # type: ignore[arg-type]
    seen_projects: set[str] = set()
    for idx, entry in enumerate(deployments):
        if not isinstance(entry, dict):
            raise ValidationError(f"deployments[{idx}] must be an object")
        row_keys = {"projectId", "version", "sourceObservedAt"}
        if set(entry) != row_keys:
            raise ValidationError(f"deployments[{idx}] keys must be exactly {sorted(row_keys)}, got {sorted(entry)}")
        pid = validate_text(entry["projectId"], f"deployments[{idx}].projectId", 255)
        if pid not in allowed_projects:
            raise ValidationError(f"deployments[{idx}].projectId {pid!r} is outside requested projectIds")
        if pid in seen_projects:
            raise ValidationError(f"Duplicate projectId {pid!r} in deployments")
        seen_projects.add(pid)
        validate_text(entry["version"], f"deployments[{idx}].version", 1024)
        validate_instant(entry["sourceObservedAt"], f"deployments[{idx}].sourceObservedAt")

    return doc


def execute_supervised(command: list[str], stdin_bytes: bytes, cwd: Path,
                       env: dict[str, str], timeout: float) -> tuple[int, bytes, bytes]:
    if not command:
        raise ValidationError("No command specified after '--'")
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        raise ValidationError(f"Failed to start command {command[0]!r}: {exc}") from exc
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    pending = memoryview(stdin_bytes)
    deadline = time.monotonic() + timeout
    timed_out = False
    overflowed: str | None = None

    def kill_group() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc.poll() is None:
            proc.kill()

    try:
        os.set_blocking(proc.stdin.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            if pending:
                selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                proc.stdin.close()

            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    kill_group()
                    break
                for key, _ in selector.select(remaining):
                    tag = key.data
                    if tag == "stdin":
                        try:
                            written = os.write(proc.stdin.fileno(), pending[:65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            selector.unregister(proc.stdin)
                            proc.stdin.close()
                            continue
                        pending = pending[written:]
                        if not pending:
                            selector.unregister(proc.stdin)
                            proc.stdin.close()
                    else:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif tag == "stdout":
                            stdout_buf.extend(chunk)
                            if len(stdout_buf) > MAX_STDOUT_BYTES:
                                overflowed = f"stdout exceeded {MAX_STDOUT_BYTES} bytes"
                                kill_group()
                                break
                        else:
                            stderr_buf.extend(chunk)
                            if len(stderr_buf) > MAX_STDERR_BYTES:
                                overflowed = f"stderr exceeded {MAX_STDERR_BYTES} bytes"
                                kill_group()
                                break
                if overflowed or timed_out:
                    break

        if timed_out:
            proc.wait()
            raise ValidationError(f"Process exceeded timeout of {timeout}s (PROCESS_TIMEOUT)")
        if overflowed:
            proc.wait()
            raise ValidationError(f"{overflowed} (OUTPUT_LIMIT_EXCEEDED)")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            kill_group()
            proc.wait()
            raise ValidationError(f"Process exceeded timeout of {timeout}s (PROCESS_TIMEOUT)")
        try:
            returncode = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            kill_group()
            proc.wait()
            raise ValidationError(f"Process exceeded timeout of {timeout}s (PROCESS_TIMEOUT)") from exc

        # Enforce the setsid rule: no detached/background descendants may outlive the leader.
        lingering = False
        try:
            os.killpg(proc.pid, 0)
            lingering = True
        except ProcessLookupError:
            lingering = False
        if lingering:
            kill_group()
            raise ValidationError(
                "Process exited while child processes remained alive in its setsid process group "
                "(PUBLICATION_UNCERTAIN)"
            )
        return returncode, bytes(stdout_buf), bytes(stderr_buf)
    finally:
        kill_group()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
        if proc.poll() is None:
            proc.wait()


def build_environment(env_items: list[str]) -> dict[str, str]:
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for item in env_items:
        if "=" not in item:
            raise ValidationError(f"Invalid --env entry (expected KEY=VALUE): {item!r}")
        key, value = item.split("=", 1)
        if not ENV_KEY_RE.fullmatch(key):
            raise ValidationError(f"Invalid environment variable name: {key!r}")
        env[key] = value
    return env


def run_negative_probes(command: list[str], valid_req: dict[str, object],
                        cwd: Path, env: dict[str, str], timeout: float) -> None:
    valid_bytes = json.dumps(valid_req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    valid_text = valid_bytes.decode("utf-8")

    # Probe 1: duplicate key
    dup_payload = (valid_text[:-1] + ',"optionId":"duplicate"}').encode("utf-8")
    # Probe 2: extra unknown field
    extra_req = dict(valid_req)
    extra_req["unexpectedField"] = "probe"
    extra_payload = json.dumps(extra_req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Probe 3: trailing JSON token
    trailing_payload = valid_bytes + b" {}"
    # Probe 4: boolean abiVersion: true
    bool_req = dict(valid_req)
    bool_req["abiVersion"] = True
    bool_payload = json.dumps(bool_req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Probe 5: ISO control character inside text field
    ctrl_req = json.loads(valid_text)
    if valid_req["operation"] == "publish":
        ctrl_req["version"] = "1.0\u0007"
    else:
        ctrl_req["projectIds"] = [f"{valid_req['projectIds'][0]}\u0007"] if valid_req["projectIds"] else ["bad\u0007"]  # type: ignore[index]
    ctrl_payload = json.dumps(ctrl_req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    probes = [
        ("duplicate-key", dup_payload),
        ("extra-field", extra_payload),
        ("trailing-json", trailing_payload),
        ("boolean-abi-version", bool_payload),
        ("control-char", ctrl_payload),
    ]
    for name, payload in probes:
        rc, out, _ = execute_supervised(command, payload, cwd, env, timeout)
        if rc == 0:
            raise ValidationError(f"Negative probe {name!r} exited 0; malformed ABI input must be rejected cleanly")
        if out.strip():
            raise ValidationError(f"Negative probe {name!r} exited {rc} with non-empty stdout")


def load_request_file(path: Path, expected_operation: str) -> dict[str, object]:
    doc = parse_strict_json_document(path.read_bytes(), label=str(path))
    if doc.get("operation") != expected_operation:
        raise ValidationError(f"Request file operation must be {expected_operation!r}")
    validate_uuid(doc.get("operationId"), "operationId")
    validate_uuid(doc.get("optionId"), "optionId")
    validate_key(doc.get("serverId"), "serverId")
    validate_key(doc.get("channelId"), "channelId")
    return doc


def strip_dashdash(args: list[str]) -> list[str]:
    if args and args[0] == "--":
        return args[1:]
    return args


def add_common_exec_args(parser: argparse.ArgumentParser, default_timeout: int) -> None:
    parser.add_argument("--working-directory", type=Path, default=Path("."))
    parser.add_argument("--timeout", type=float, default=float(default_timeout))
    parser.add_argument("--env", action="append", default=[], help="Extra cleared-env variable (KEY=VALUE)")
    parser.add_argument("--probe-negative-inputs", action="store_true",
                        help="Also verify the script rejects malformed ABI v1 inputs cleanly")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="subcommand", required=True)

    pub = sub.add_parser("publish", help="Execute and validate a publish script")
    pub.add_argument("--request-file", type=Path)
    pub.add_argument("--operation-id", default=str(uuid.uuid4()))
    pub.add_argument("--option-id", default="00000000-0000-0000-0000-000000000028")
    pub.add_argument("--server-id", default="test")
    pub.add_argument("--channel-id", default="candidate")
    pub.add_argument("--project-id", default="sample-project")
    pub.add_argument("--version", default="1.0.0")
    pub.add_argument("--expect-outcome", choices=sorted(OUTCOMES))
    pub.add_argument("--expect-error-code", choices=sorted(SAFE_SCRIPT_ERROR_CODES))
    add_common_exec_args(pub, 30)
    pub.add_argument("command", nargs=argparse.REMAINDER)

    inv = sub.add_parser("inventory", help="Execute and validate an inventory script")
    inv.add_argument("--request-file", type=Path)
    inv.add_argument("--operation-id", default=str(uuid.uuid4()))
    inv.add_argument("--option-id", default="00000000-0000-0000-0000-000000000028")
    inv.add_argument("--server-id", default="test")
    inv.add_argument("--channel-id", default="candidate")
    inv.add_argument("--project-id", dest="project_ids", action="append", default=[])
    inv.add_argument("--purpose", choices=["REFRESH", "VERIFY"], default="VERIFY")
    inv.add_argument("--require-authoritative", action="store_true")
    add_common_exec_args(inv, 30)
    inv.add_argument("command", nargs=argparse.REMAINDER)

    vj = sub.add_parser("validate-json", help="Validate a captured script stdout JSON file against a request file")
    vj.add_argument("--operation", choices=["publish", "inventory"], required=True)
    vj.add_argument("--request-file", type=Path, required=True)
    vj.add_argument("--response-file", type=Path, help="Read stdout bytes from file instead of stdin")
    vj.add_argument("--require-authoritative", action="store_true")
    vj.add_argument("--expect-outcome", choices=sorted(OUTCOMES))
    vj.add_argument("--expect-error-code", choices=sorted(SAFE_SCRIPT_ERROR_CODES))

    args = parser.parse_args(argv)
    try:
        if args.subcommand == "validate-json":
            req = load_request_file(args.request_file, args.operation)
            raw = args.response_file.read_bytes() if args.response_file else sys.stdin.buffer.read(MAX_STDOUT_BYTES + 1)
            if args.operation == "publish":
                validated = validate_publish_result(raw, req["operationId"], args.expect_outcome, args.expect_error_code)  # type: ignore[arg-type]
            else:
                validated = validate_inventory_result(raw, req, require_authoritative=args.require_authoritative)
            print(json.dumps({"valid": True, "operation": args.operation, "response": validated}, indent=2))
            return 0

        command = strip_dashdash(args.command)
        if not command:
            raise ValidationError("Provide the script command after '--'")
        max_timeout = MAX_PUBLISH_TIMEOUT if args.subcommand == "publish" else MAX_INVENTORY_TIMEOUT
        if args.timeout <= 0 or args.timeout > max_timeout:
            raise ValidationError(f"Timeout must be in (0, {max_timeout}] seconds")

        cwd = args.working_directory.resolve()
        env = build_environment(args.env)

        if args.subcommand == "publish":
            if args.request_file:
                req = load_request_file(args.request_file, "publish")
            else:
                req = {
                    "abiVersion": 1,
                    "operation": "publish",
                    "operationId": validate_uuid(args.operation_id, "operation-id"),
                    "optionId": validate_uuid(args.option_id, "option-id"),
                    "serverId": validate_key(args.server_id, "server-id"),
                    "channelId": validate_key(args.channel_id, "channel-id"),
                    "projectId": validate_text(args.project_id, "project-id", 255),
                    "version": validate_text(args.version, "version", 1024),
                }
            payload = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            rc, out, err = execute_supervised(command, payload, cwd, env, args.timeout)
            if rc != 0:
                diag = err.decode("utf-8", errors="replace").strip()
                raise ValidationError(f"Publish script exited with status {rc}" + (f": {diag}" if diag else ""))
            validated = validate_publish_result(out, req["operationId"], args.expect_outcome, args.expect_error_code)  # type: ignore[arg-type]
            if args.probe_negative_inputs:
                run_negative_probes(command, req, cwd, env, args.timeout)
            print(json.dumps({"valid": True, "operation": "publish", "response": validated}, indent=2))
            return 0

        if args.request_file:
            req = load_request_file(args.request_file, "inventory")
        else:
            projects = args.project_ids or ["sample-project"]
            if len(projects) > MAX_PROJECTS or len(projects) != len(set(projects)):
                raise ValidationError("project-id values must be unique and at most 20000")
            req = {
                "abiVersion": 1,
                "operation": "inventory",
                "operationId": validate_uuid(args.operation_id, "operation-id"),
                "optionId": validate_uuid(args.option_id, "option-id"),
                "serverId": validate_key(args.server_id, "server-id"),
                "channelId": validate_key(args.channel_id, "channel-id"),
                "projectIds": [validate_text(p, "project-id", 255) for p in projects],
                "purpose": args.purpose,
            }
        payload = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_STDOUT_BYTES:
            raise ValidationError(f"Request exceeds {MAX_STDOUT_BYTES} bytes")
        rc, out, err = execute_supervised(command, payload, cwd, env, args.timeout)
        if rc != 0:
            diag = err.decode("utf-8", errors="replace").strip()
            raise ValidationError(f"Inventory script exited with status {rc}" + (f": {diag}" if diag else ""))
        validated = validate_inventory_result(out, req, require_authoritative=args.require_authoritative)
        if args.probe_negative_inputs:
            run_negative_probes(command, req, cwd, env, args.timeout)
        print(json.dumps({"valid": True, "operation": "inventory", "response": validated}, indent=2))
        return 0
    except ValidationError as exc:
        print(f"ABI validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
