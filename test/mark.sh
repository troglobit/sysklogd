#!/bin/sh -e
# Test '-- MARK --' in log, depends on fwd.sh
# shellcheck disable=SC1090
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

# Enable MARK messages every minute, full secure mode
setup -m1 -ss

check_mark()
{
    grep "MARK" "${LOG}" && return 0
    sleep 1
    return 1
}

tenacious 120 check_mark && OK
FAIL "Missing MARK in log"
