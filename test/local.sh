#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

MSG="foobar"

../src/logger -u ${SOCK} ${MSG}

grep ${MSG} ${LOG}
