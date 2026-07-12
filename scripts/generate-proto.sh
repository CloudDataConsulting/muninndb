#!/usr/bin/env sh
set -eu

readonly required_buf_version="1.71.0"
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if ! command -v buf >/dev/null 2>&1; then
  echo "buf ${required_buf_version} is required; use the pinned hosted workflow" >&2
  exit 1
fi

actual_buf_version=$(buf --version)
if [ "$actual_buf_version" != "$required_buf_version" ]; then
  echo "buf ${required_buf_version} is required, found ${actual_buf_version}" >&2
  exit 1
fi

buf build proto
buf generate --template buf.gen.yaml
