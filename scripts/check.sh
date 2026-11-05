#!/usr/bin/env bash
# Runs the checks that CI runs on every operating system. Run this before
# opening a pull request.
set -euo pipefail
cd "$(dirname "$0")/.."

min_coverage=95
profile=coverage.out
trap 'rm -f "$profile"' EXIT

echo "==> gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "these files need gofmt:"
	echo "$unformatted"
	exit 1
fi

echo "==> go mod tidy"
go mod tidy -diff

echo "==> go vet"
go vet ./...

echo "==> go build"
go build ./...

echo "==> go test"
go test -count=1 -coverprofile="$profile" ./...

echo "==> coverage"
total=$(go tool cover -func="$profile" | awk '/^total:/ { sub("%", "", $3); print $3 }')
if ! awk -v total="$total" -v min="$min_coverage" 'BEGIN { exit !(total >= min) }'; then
	echo "coverage is ${total}%, below the ${min_coverage}% minimum"
	exit 1
fi
echo "coverage is ${total}%"

echo "All checks passed."
