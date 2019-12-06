#!/bin/sh -e
# Test '-- MARK --' in log, depends on fwd.sh

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

sleep 120
grep "MARK" ${LOG2}
