#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/keycover-crypto-tests.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM

swiftc -module-cache-path "$test_directory/module-cache" \
    "$repo_root/PlayCover/Utils/KeyCoverCrypto.swift" \
    "$repo_root/Tests/KeyCoverCryptoTests.swift" \
    -o "$test_directory/keycover-crypto-tests"
"$test_directory/keycover-crypto-tests"
