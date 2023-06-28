#!/usr/bin/env bash
set -euxo pipefail

go install github.com/elastic/go-licenser@latest
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

# Run the tests
useradd -m -s /bin/bash testuser
set +e
mkdir -p build
go install github.com/jstemmer/go-junit-report@latest
export OUT_FILE="build/test-report.out"
command="$(go list ./... | grep -v /vendor/)"
su -c "go test ${command//$'\n'/' '} | tee ${OUT_FILE}" testuser
status=$?
go-junit-report > "build/junit.xml" < ${OUT_FILE}

OUT_FILE="build/test-report-386.out"
su -c "GOARCH=386 go test ${command//$'\n'/' '} | tee ${OUT_FILE}" testuser
# GOARCH=386 go test $(go list ./... | grep -v /vendor/) | tee ${OUT_FILE}
if [ $? -gt 0 ] ; then
    status=1
fi
go-junit-report > "build/junit-386.xml" < ${OUT_FILE}
if [ $status -gt 0 ] ; then
    exit 1
fi
set -x

mkdir -p build/bin
go build -o build/bin/audit ./cmd/audit/
go build -o build/bin/auparse ./cmd/auparse/
