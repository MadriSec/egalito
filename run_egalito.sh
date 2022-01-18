#!/bin/bash -e
# A short helper script to run egalito->gtirb->pprinter and organize outputs
set -e

INPUT_BINARY="$1"
OUTPUT_DIR="$2"
VARIANT="$3"

BINARY_NAME="$(basename $INPUT_BINARY)"

if [[ "$OUTPUT_DIR" == "" ]]; then
    echo "Usage: $0 INPUT_BINARY OUTPUT_DIR [VARIANT]"
    exit 1
fi

BIN_OUTPUT="$OUTPUT_DIR/$BINARY_NAME"
mkdir -p  $BIN_OUTPUT
HERE="$(dirname $0)"
set -x
cp $INPUT_BINARY $BIN_OUTPUT/original
LABEL="original"
if [[ "$VARIANT" != "" ]]; then
    LABEL="${VARIANT// /_}"
    set -x
    ./app/build_x86_64/$VARIANT $BIN_OUTPUT/original $BIN_OUTPUT/$LABEL
fi

mkdir -p $BIN_OUTPUT/egalito

reassemble() {
    # In theory, the default reconstruction policy should exclude these symbols
    # In practice, it does not, so excluding them manually allows the binary to be created
    if ! gtirb-pprinter \
        --skip-section .plt \
        --skip-symbol __FRAME_END__ \
        --skip-symbol _fini \
        --skip-symbol _start \
        --ir $1.gtirb -b $1 -a $1.s; then
        echo "Construction of binary from $1 failed"
    fi
    # Attempt to build it with all included symbols
    # (Currently causes this error when the binary is run: unsupported version 0 of Verneed record)
    if ! gtirb-pprinter --policy complete --ir $1.gtirb  -b $1-rebuilt-complete; then
        echo "Reassembly of $1 failed"
    fi
    if ! gtirb-pprinter --ir $1.gtirb --keep-all -a $1-all.s; then
        echo "Construction of assembly ('--keep-all') from $1 failed"
    fi
}

# Color all stderr output that doesn't start with '+'
# (so '-x' outputs doesn't look like it's warnings)
exec 2> >(sed $'s|\(^[^\+].*\)|\e\[31m\\1\e[m|g' 2>&1 )
set -x
${DOGDB+gdb --args} $HERE/app/build_x86_64/etgtirb $BIN_OUTPUT/$LABEL $BIN_OUTPUT/egalito/$LABEL

reassemble $BIN_OUTPUT/egalito/$LABEL