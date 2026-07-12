#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [ -n "$(git status --short -- \
  proto/gen/go/muninn/v1/service.pb.go \
  proto/gen/go/muninn/v1/service_grpc.pb.go)" ]; then
  echo "canonical protobuf output is stale:" >&2
  git status --short -- \
    proto/gen/go/muninn/v1/service.pb.go \
    proto/gen/go/muninn/v1/service_grpc.pb.go >&2
  echo "download the canonical-go-stubs workflow artifact and commit it" >&2
  exit 1
fi
