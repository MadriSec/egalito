#!/bin/bash -e
# A short helper script to run egalito->gtirb->pprinter and organize outputs
set -e

INPUT_BINARY="$1"
OUTPUT_DIR="$2"
VARIANT="$3"

THIS_DIR="$(dirname $0)"
APP_DIR="$THIS_DIR/../../app/build_x86_64"

if [[ "$OUTPUT_DIR" == "" ]]; then
    echo "Usage: $0 INPUT_BINARY OUTPUT_DIR [VARIANT]"
    exit 1
fi

BINARY_NAME="$(basename $INPUT_BINARY)"
BIN_OUTPUT="$OUTPUT_DIR/$BINARY_NAME"
mkdir -p  $BIN_OUTPUT
set -x
cp $INPUT_BINARY $BIN_OUTPUT/original
LABEL="original"
if [[ "$VARIANT" != "" ]]; then
    LABEL="${VARIANT// /_}"
    set -x
    "$APP_DIR/$VARIANT" $BIN_OUTPUT/original $BIN_OUTPUT/$LABEL
fi

mkdir -p $BIN_OUTPUT/egalito

reassemble() {
    # In theory, the default reconstruction policy should exclude these symbols
    # In practice, it does not, so excluding them manually allows the binary to be created
    if ! gtirb-pprinter \
        --dummy-so 1 \
        --syntax att \
        --skip-section .plt \
        --skip-symbol __FRAME_END__ \
        --skip-symbol _fini \
        --skip-symbol _start \
        --ir $1.gtirb -b $1-rebuilt -a $1.s; then
        echo "Construction of binary from $1 failed"
    fi
    # Attempt to build it with all included symbols
    # (Currently causes this error when the binary is run: unsupported version 0 of Verneed record)
    if ! gtirb-pprinter \
        --dummy-so 1 \
        --syntax att \
        --policy complete \
        --ir $1.gtirb  -b $1-rebuilt-complete -a $1-complete.s; then
        echo "Reassembly of $1 failed"
    fi
}

# Color all stderr output that doesn't start with '+'
# (so '-x' outputs doesn't look like it's warnings)
exec 2> >(sed $'s|\(^[^\+].*\)|\e\[31m\\1\e[m|g' 2>&1 )
set -x
${DOGDB+gdb --args} "$APP_DIR/etgtirb" --deep $BIN_OUTPUT/$LABEL $BIN_OUTPUT/egalito/$LABEL

reassemble $BIN_OUTPUT/egalito/$LABEL
