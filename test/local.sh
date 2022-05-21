#!/bin/sh
# shellcheck disable=SC1090

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi

. ${srcdir}/lib.sh
setup

print "TEST: Starting"

MSG="foobar"
MSG2="xyzzy"

logger "${MSG}"
grep ${MSG} "${LOG}" || FAIL "Cannot find: ${MSG}"

logger "${ALTSOCK}" ${MSG2}
grep ${MSG2} "${LOG}" || FAIL "Cannot find: ${MSG2}"

OK
