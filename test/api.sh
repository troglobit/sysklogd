#!/bin/sh
set -e
. ./test.rc

export MSG="no-openlog-apitest"
./api
grep "api ${MSG}" ${LOG}
