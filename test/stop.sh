#!/bin/sh
. ./test.rc

if [ -e ${PID} ]; then
    kill `cat ${PID}`
fi

rm -f ${CFG}
rm -f ${LOG}
rm -f ${PID}
rm -f ${SCK}
