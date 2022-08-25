#!/usr/bin/env bash
set -euxo pipefail

go get -d -t ./...
go mod download

go test -count=5 -benchmem -run=XXX -benchtime=100ms -bench='.*' -v $(go list ./... | grep -v /vendor/) | tee bench.out
