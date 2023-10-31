#!/usr/bin/env bash
set -euxo pipefail

go mod download
go mod verify

go test -count=5 -benchmem -run=XXX -benchtime=100ms -bench='.*' -v $(go list ./... | grep -v /vendor/) | tee bench.out
