@echo off
REM Run tests the same way as CI (CGO enabled so SQLite-backed tests run).
REM Requires a C compiler (e.g. MinGW-w64 gcc) in PATH. Without it, set CGO_ENABLED=0 to skip DB tests.
set CGO_ENABLED=1
go mod download
go mod verify
go test -v ./... -count=1
