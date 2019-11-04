#!/bin/sh
. ${srcdir}/test.rc

MSG="foobar"

../src/logger -u ${SOCK} ${MSG}

grep ${MSG} ${LOG}
