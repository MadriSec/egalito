#!/bin/bash
# Run etgtirb and gtirb pprinter to disassemble and re-assemble a binary
# and ensure that the output matches prior to disassembly

ensure_match() {
    ORIG="$1"
    NEW="$2"

    if [[ ! -f "$NEW" ]]; then
        echo "$NEW does not exist"
        return 1;
    fi

    $ORIG > $ORIG.stdout 2> $ORIG.stderr
    ORIG_RTN="$?"
    $NEW > $NEW.stdout 2> $NEW.stderr
    NEW_RTN="$?"

    if [[ "$ORIG_RTN" != "$NEW_RTN" ]]; then
        echo "Return code changed from $ORIG_RTN to $NEW_RTN"
        return 1
    fi

    if [[ $RTN_ONLY == 1 ]]; then
        return 0
    fi

    if ! cmp $ORIG.stdout $NEW.stdout; then
        echo "STDOUT changed from:"
        cat $ORIG.stdout
        echo "to:"
        cat $NEW.stdout
        return 1
    fi

    if ! cmp $ORIG.stderr $NEW.stderr; then
        echo "STDERR change from:"
        cat stderr
        echo "to:"
        cat egalito/stderr
        return 1
    fi

}

THIS_DIR="$(dirname $0)"

EX_DIR="$THIS_DIR/../../src/ex"

echo "Testing ex: 'hello'"
$THIS_DIR/egal2gtirb.sh $EX_DIR/hello test_output > /dev/null 2>/dev/null
(
    cd test_output/hello
    if ! ensure_match ./original ./egalito/original-rebuilt; then
        exit
    fi
)

echo "Testing ex: 'hi0'"
$THIS_DIR/egal2gtirb.sh $EX_DIR/hi0 test_output > /dev/null 2>/dev/null
(
    cd test_output/hi0
    if ! ensure_match ./original ./egalito/original-rebuilt; then
        exit
    fi
)

# islower prints a pointer address so the output changes slightly each time
echo "Testing ex: 'islower'"
$THIS_DIR/egal2gtirb.sh $EX_DIR/islower test_output > /dev/null 2>/dev/null
(
    cd test_output/islower
    if ! RTN_ONLY=1 ensure_match ./original ./egalito/original-rebuilt; then
        exit
    fi
)

# getenv prints a pointer address so the output changes slightly each time
echo "Testing ex: 'getenv'"
$THIS_DIR/egal2gtirb.sh $EX_DIR/getenv test_output > /dev/null 2>/dev/null
(
    cd test_output/getenv
    if ! RTN_ONLY=1 ensure_match ./original ./egalito/original-rebuilt; then
        exit
    fi
)


# 'complete' output only works if there are no library calls
# The 'hi5' binary doesn't have stdlib,
# so 'complete' works but the default strategy does not
echo "Testing ex: 'hi5'"
$THIS_DIR/egal2gtirb.sh $EX_DIR/hi5 test_output > /dev/null 2>/dev/null
(
    cd test_output/hi5
    if ! ensure_match ./original ./egalito/original-rebuilt-complete; then
        exit
    fi
)
