#!/usr/bin/env bash
# Insert an AArch64 call into main, generate an ELF, and run it.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

if [ "$(uname -m)" != aarch64 ]; then
    echo "This check must run on AArch64 Linux." >&2
    exit 2
fi

keep_artifacts=0
if [ "${1:-}" = --keep ]; then
    keep_artifacts=1
    shift
fi
if [ "$#" -ne 0 ]; then
    echo "usage: $0 [--keep]" >&2
    exit 2
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/egalito-instrument-aarch64.XXXXXX")
cleanup() {
    status=$?
    if [ "$status" -eq 0 ] && [ "$keep_artifacts" -eq 0 ]; then
        rm -r -- "$workdir"
    else
        echo "Logs and generated executables kept at: $workdir"
    fi
}
trap cleanup EXIT

gcc -fPIE -pie -O0 -fno-omit-frame-pointer \
    test/integration/aarch64-instrument-entry.c -o "$workdir/original"

g++ -std=c++17 -DARCH_AARCH64 \
    -I src -I dep/capstone/install/include \
    test/integration/aarch64-instrument-entry.cpp \
    -L src/build_aarch64 -legalito \
    -L dep/capstone/install/lib -lcapstone -lstdc++fs \
    -Wl,-rpath,"$repo_root/src/build_aarch64" \
    -Wl,-rpath,"$repo_root/dep/capstone/install/lib" \
    -o "$workdir/rewrite"

"$workdir/original" > "$workdir/original.out"
printf 'main\n' | cmp - "$workdir/original.out"

"$workdir/rewrite" "$workdir/original" "$workdir/instrumented" \
    > "$workdir/rewrite.log" 2>&1
grep -qx 'inserted_calls=1' "$workdir/rewrite.log"
test -x "$workdir/instrumented"

objdump -d "$workdir/original" \
    | sed -n '/<main>:/,/^$/p' > "$workdir/original-main.asm"
objdump -d "$workdir/instrumented" \
    | sed -n '/<main>:/,/^$/p' > "$workdir/instrumented-main.asm"
call_pattern='[[:space:]]bl[[:space:]]+.*<entryAdvice>'
if grep -Eq "$call_pattern" "$workdir/original-main.asm"; then
    echo "FAIL: original main already calls entryAdvice" >&2
    exit 1
fi
if ! grep -Eq "$call_pattern" "$workdir/instrumented-main.asm"; then
    echo "FAIL: generated main has no BL to entryAdvice" >&2
    exit 1
fi
if ! grep -Eq '[[:space:]]bl[[:space:]]+.*<puts@plt>' \
    "$workdir/instrumented-main.asm"; then
    echo "FAIL: generated main does not call the correctly labelled puts PLT entry" >&2
    exit 1
fi

"$workdir/instrumented" > "$workdir/instrumented.out"
printf 'advice\nmain\n' | cmp - "$workdir/instrumented.out"

grep -E "$call_pattern" "$workdir/instrumented-main.asm"
echo "PASS: one call was inserted into main and executed"
