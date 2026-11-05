#!/usr/bin/env bash
# Runs the checks that CI runs on every operating system. Run this before
# opening a pull request. The browser module's tests need Chrome, and skip
# themselves without it unless CI is set.
set -euo pipefail
cd "$(dirname "$0")/.."

profile=coverage.out
trap 'rm -f "$profile" "browser/$profile"' EXIT

echo "==> gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "these files need gofmt:"
	echo "$unformatted"
	exit 1
fi

# check_module runs the checks for the module in directory $1, which must have
# at least $2 percent test coverage.
check_module() {
	local dir=$1 min_coverage=$2 total
	pushd "$dir" >/dev/null

	echo "==> $dir: go mod tidy"
	go mod tidy -diff

	echo "==> $dir: go vet"
	go vet ./...

	echo "==> $dir: go build"
	go build ./...

	echo "==> $dir: go test"
	go test -count=1 -coverprofile="$profile" ./...

	echo "==> $dir: coverage"
	total=$(go tool cover -func="$profile" | awk '/^total:/ { sub("%", "", $3); print $3 }')
	if ! awk -v total="$total" -v min="$min_coverage" 'BEGIN { exit !(total >= min) }'; then
		echo "coverage is ${total}%, below the ${min_coverage}% minimum"
		exit 1
	fi
	echo "coverage is ${total}%"

	popd >/dev/null
}

check_module . 95
# Lower because most of what's untested handles Chrome failing mid-session.
check_module browser 85

echo "All checks passed."
