#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 1. afl-patched vmndh sends coverage info and segfault signals
$DIR/scripts/bpatch.py $DIR/examples/vmndh/vmndh $DIR/examples/vmndh/tramp*.c $DIR/examples/vmndh/out && \
    echo -ne '__AFL_SHM_ID\x00' >> $DIR/examples/vmndh/out/vmndh.new &&
    echo 'Built afl-patched vmndh!' && \
    $DIR/examples/vmndh/out/vmndh.new -file $DIR/examples/vmndh/exploitme1 -arg "`python -c 'print "A" * 50'`"

# 2. upper-cased bash hooks fwrite and emit uppercase characters
$DIR/scripts/bpatch.py $DIR/examples/bash/bash $DIR/examples/bash/tramp*.c $DIR/examples/bash/out && \
    echo 'Enjoy your upper-cased shell!' && \
    $DIR/examples/bash/out/bash.new
