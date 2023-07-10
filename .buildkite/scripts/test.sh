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
go install github.com/jstemmer/go-junit-report@latest
IS_TEST_FAIL=false
run_test_prepare_junit() {
    local temporary_file="build/test-report.out"
    local junit_output=${1:-test-report.out}
    local root=${2:-false}
    local go_env=${3:-''} # e.g. GOARCH=386
    set +e
    list="$(go list ./... | grep -v /vendor/)"
    list_string="${list//$'\n'/ }"
    if [[ $root == "true" ]]; then
        ${go_env} go test -v ${list_string} | tee ${temporary_file}
        [[ $? -gt 0 ]] && IS_TEST_FAIL=true
    else
        useradd -m -s /bin/bash testuser
        su -c "${go_env} go test -v ${list_string}" testuser | tee ${temporary_file}
        [[ $? -gt 0 ]] && IS_TEST_FAIL=true
        userdel testuser
    fi
    go-junit-report > "${junit_output}" < ${temporary_file}
    set -e
}

mkdir -p build
run_test_prepare_junit "build/junit-noroot.xml" false
run_test_prepare_junit "build/junit-386-noroot.xml" false "GOARCH=386"

if [[ ${IS_TEST_FAIL} == 'true' ]]; then
    echo "TESTS FAIL"
    exit 1
fi

# Check build
mkdir -p build/bin
go build -o build/bin/audit ./cmd/audit/
go build -o build/bin/auparse ./cmd/auparse/
