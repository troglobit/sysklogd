#!/bin/sh
# Verify logger capabilities, for now just remote logger
# shellcheck disable=SC1090
#set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
ip link set lo up

print "Starting stand-alone logger test ..."
cap_start
logger -b -H "$(basename "$0")" -h 127.0.0.3 -I $$ -t test1 "Kilroy was here"
cap_stop

# Check for the composed BSD procname{PID] syntax
STR="test1\[$$\]"
cap_find "$STR" || FAIL "Cannot find: $STR"

OK
