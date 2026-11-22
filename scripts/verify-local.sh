#!/usr/bin/env bash
# Offline disposable verification suite for all starter templates and ABI tooling.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ $# != 0 ]]; then
  echo "Usage: scripts/verify-local.sh" >&2
  exit 2
fi

[[ $(uname -s) == Linux ]] || { echo "Linux is required" >&2; exit 1; }
for dependency in python3 docker; do
  command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 1; }
done
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"'
docker info >/dev/null

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git --no-pager diff --check
fi

image="publishd-runner-examples-tests:local-$(date -u +%Y%m%d%H%M%S)-$$"
trap 'docker image rm "$image" >/dev/null 2>&1 || true' EXIT

docker build -f tests/Dockerfile -t "$image" .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev "$image"
