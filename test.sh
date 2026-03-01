#!/usr/bin/env sh
# Run tests the same way as CI (CGO enabled so SQLite-backed tests run).
# Requires a C compiler (e.g. gcc). On macOS/Linux one is usually present.
set -e
export CGO_ENABLED=1
go mod download
go mod verify
go test -v ./... -count=1
