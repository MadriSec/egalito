#!/bin/bash -e

set -e
exec 2> >(sed $'s|\(\+ .*\)\{0,1\}\(.*\)|\e\[32m\\1\e[m\e\[31m\\2\e[m|g' 2>&1 )

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


cp $INPUT_BINARY $BIN_OUTPUT/original
LABEL="original"
set -x
if [[ "$VARIANT" != "" ]]; then
    LABEL="${VARIANT// /_}"
    if [[ -e "$BIN_OUTPUT/$LABEL" ]]; then
        echo "Not remaking $BIN_OUTPUT/$LABEL"
        sleep 1
    else 
        set -x
        ./app/build_x86_64/$VARIANT $BIN_OUTPUT/original $BIN_OUTPUT/$LABEL
    fi
fi

mkdir -p $BIN_OUTPUT/ddisasm

reassemble() {
    if ! gtirb-pprinter --keep-all --ir $1.gtirb -a $1-all.s; then
        echo "Construction of assembly from $1 failed"
    fi
    if ! gtirb-pprinter --policy complete --ir $1.gtirb -a $1-complete.s; then
        echo "Construction of assembly from $1 failed"
    fi
    if ! gtirb-pprinter --ir $1.gtirb -b $1-rebuilt; then
        echo "Reassembly of $1 failed"
    fi
    if ! gtirb-pprinter --policy complete --ir $1.gtirb -b $1-complete-rebuilt; then
        echo "Reassembly of $1 failed"
    fi
}

# Color all stderr output that doesn't start with '+'
# (so '-x' outputs doesn't look like it's warnings)
exec 2> >(sed $'s|\(^[^\+].*\)|\e\[31m\\1\e[m|g' 2>&1 )
set -x
ddisasm --no-cfi-directives  $BIN_OUTPUT/$LABEL --ir $BIN_OUTPUT/ddisasm/$LABEL.gtirb --json $BIN_OUTPUT/ddisasm/$LABEL.json --asm $BIN_OUTPUT/ddisasm/$LABEL.s

reassemble $BIN_OUTPUT/ddisasm/$LABEL
