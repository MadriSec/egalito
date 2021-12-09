#!/bin/bash -e
set -e
exec 2> >(sed $'s|\(\+ .*\)\{0,1\}\(.*\)|\e\[32m\\1\e[m\e\[31m\\2\e[m|g' 2>&1 )
#exec 2> >(sed $'s,.*,\e[31m&\e[m,g' >&2) # | sed $'s,^[^+].*,\e[31m&\e[m,' >&2)

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
    if ! gtirb-pprinter --ir $1.gtirb -a $1.s; then
        echo "Construction of assembly from $1 failed"
    fi
    if ! gtirb-pprinter --ir $1.gtirb -b $1; then
        echo "Construction of binary from $1 failed"
    fi
    if ! gtirb-pprinter -k --ir $1.gtirb -a $1-all.s; then
        echo "Construction of assembly ('--keep-all') from $1 failed"
    fi
    if ! gtirb-pprinter --policy complete --ir $1.gtirb -a $1-complete.s; then
        echo "Constructin of assembly (complete) of $1 failed"
    fi
    if ! gtirb-pprinter --policy complete --ir $1.gtirb -b $1-rebuilt-complete; then
        echo "Reassembly of $1 failed"
    fi
}

set -x
$HERE/app/build_x86_64/etgtirb $BIN_OUTPUT/$LABEL $BIN_OUTPUT/egalito/$LABEL

reassemble $BIN_OUTPUT/egalito/$LABEL

#echo "Attempting deep"
#read
#$HERE/app/build_x86_64/etgtirb --deep $BIN_OUTPUT/$LABEL $BIN_OUTPUT/egalito/$LABEL-deep
#reassemble $BIN_OUTPUT/egalito/$LABEL-deep

#reassemble $BIN_OUTPUT/egalito/$LABEL-deep
