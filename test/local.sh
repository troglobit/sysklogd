#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
setup

print "TEST: Starting"

MSG="foobar"
MSG2="xyzzy"

../src/logger -u ${SOCK} ${MSG}
grep ${MSG} ${LOG} || FAIL "Cannot find: ${MSG}"

../src/logger -u ${ALTSOCK} ${MSG2}
grep ${MSG2} ${LOG} || FAIL "Cannot find: ${MSG2}"
OK
