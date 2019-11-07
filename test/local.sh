#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

MSG="foobar"
MSG2="xyzzy"

../src/logger -u ${SOCK} ${MSG}
grep ${MSG} ${LOG}

../src/logger -u ${ALTSOCK} ${MSG2}
grep ${MSG2} ${LOG}
