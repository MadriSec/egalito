#!/usr/bin/env bash
# Compare named direct-call edges from Egalito's CallGraph on each native host.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

case "$(uname -m)" in
    aarch64) arch=aarch64; arch_macro=ARCH_AARCH64 ;;
    x86_64) arch=x86_64; arch_macro=ARCH_X86_64 ;;
    *) echo "This check requires x86-64 or AArch64 Linux." >&2; exit 2 ;;
esac
if [ "$(uname -s)" != Linux ]; then
    echo "This check requires Linux." >&2
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

workdir=$(mktemp -d "${TMPDIR:-/tmp}/egalito-fcg-${arch}.XXXXXX")
cleanup() {
    status=$?
    if [ "$status" -eq 0 ] && [ "$keep_artifacts" -eq 0 ]; then
        rm -r -- "$workdir"
    else
        echo "FCG output and logs kept at: $workdir"
    fi
}
trap cleanup EXIT

gcc -fPIE -pie -O0 -fno-inline \
    test/integration/fcg-example.c -o "$workdir/example"
"$workdir/example"
g++ -std=c++17 "-D$arch_macro" \
    -I src -I dep/capstone/install/include \
    test/integration/fcg-edges.cpp \
    "-Lsrc/build_$arch" -legalito \
    -L dep/capstone/install/lib -lcapstone -lstdc++fs \
    "-Wl,-rpath,$repo_root/src/build_$arch" \
    "-Wl,-rpath,$repo_root/dep/capstone/install/lib" \
    -o "$workdir/fcg-edges"

"$workdir/fcg-edges" "$workdir/example" \
    > "$workdir/edges.txt" 2> "$workdir/fcg.log"
cat > "$workdir/expected.txt" <<'EOF'
fcg_left -> fcg_leaf
main -> fcg_left
main -> fcg_right
EOF
diff -u "$workdir/expected.txt" "$workdir/edges.txt"
cat "$workdir/edges.txt"
echo "PASS: Egalito generated the expected direct-call edges on $arch"
