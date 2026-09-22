#!/usr/bin/env bash
# Compare AArch64 example programs with their Egalito mirror outputs.
set -u

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root" || exit 1

if [ "$(uname -m)" != aarch64 ]; then
    echo "This check must run on AArch64 Linux." >&2
    exit 2
fi

keep_artifacts=0
if [ "${1:-}" = --keep ]; then
    keep_artifacts=1
    shift
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/egalito-mirror-aarch64.XXXXXX") || exit 1
cleanup() {
    status=$?
    if [ "$status" -eq 0 ] && [ "$keep_artifacts" -eq 0 ]; then
        rm -r -- "$workdir"
    else
        echo "Logs and generated executables kept at: $workdir"
    fi
}
trap cleanup EXIT

if [ "$#" -eq 0 ]; then
    set -- hello hello-strip hi0 hi0-strip hi5 fp jumptable islower \
        stderr stack log
fi

failures=0
for name in "$@"; do
    original="test/example/build_aarch64/$name"
    mirror="$workdir/$name-mirror"
    if [ ! -x "$original" ]; then
        echo "FAIL $name: original executable is missing ($original)"
        failures=$((failures + 1))
        continue
    fi

    if "$original" >"$workdir/$name.original.out" 2>&1; then
        original_status=0
    else
        original_status=$?
    fi

    if ! ./app/etelf -m "$original" "$mirror" \
        >"$workdir/$name.etelf.log" 2>&1 || [ ! -x "$mirror" ]; then
        echo "FAIL $name: mirror generation failed (see $workdir/$name.etelf.log)"
        failures=$((failures + 1))
        continue
    fi

    if "$mirror" >"$workdir/$name.mirror.out" 2>&1; then
        mirror_status=0
    else
        mirror_status=$?
    fi

    if [ "$original_status" -eq "$mirror_status" ] \
        && cmp -s "$workdir/$name.original.out" "$workdir/$name.mirror.out"; then
        echo "PASS $name (exit $mirror_status, output identical)"
    else
        echo "FAIL $name (original exit $original_status, mirror exit $mirror_status)"
        diff -u "$workdir/$name.original.out" "$workdir/$name.mirror.out" || true
        failures=$((failures + 1))
    fi
done

echo "$failures failure(s)"
[ "$failures" -eq 0 ]
