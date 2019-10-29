#!/bin/sh
. ./test.rc

MSG="foobar"

../src/logger -u ${SCK} ${MSG}

grep ${MSG} ${LOG}
