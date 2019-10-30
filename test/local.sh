#!/bin/sh
. ./test.rc

MSG="foobar"

../src/logger -u ${SOCK} ${MSG}

grep ${MSG} ${LOG}
