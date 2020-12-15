#!/usr/bin/env bash
set -euxo pipefail

GO111MODULE=off go get -u github.com/elastic/go-licenser
go get -d -t ./...
go mod download
go mod verify

if go mod tidy ; then
    if [ -z "$(git status --porcelain go.mod go.sum)" ] ; then
        echo "Go module manifest has not changed."
    else 
        echo "Go module manifest changed. Run 'go mod tidy'" 1>&2
        exit 1
    fi
fi
go-licenser -d

if find . -name '*.go' | grep -v vendor | xargs gofmt -s -l | read ; then
    echo "Code differs from gofmt's style. Run 'gofmt -s -w .'" 1>&2 
    exit 1
fi

go test -v $(go list ./... | grep -v /vendor/)
GOARCH=386 go test -v $(go list ./... | grep -v /vendor/)
mkdir -p build/bin
go build -o build/bin/audit ./cmd/audit/
go build -o build/bin/auparse ./cmd/auparse/