#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

./scripts/generate-proto.sh

if [ -n "$(git status --short -- proto/gen/go)" ]; then
  echo "canonical protobuf output is stale:" >&2
  git status --short -- proto/gen/go >&2
  echo "download the canonical-go-stubs workflow artifact and commit it" >&2
  exit 1
fi
