#!/bin/sh
. ./test.rc

if [ -e ${PID} ]; then
    echo "Killing `cat ${PID}` ..."
    kill `cat ${PID}`
fi

rm -f ${LOG}
rm -f ${PID}
rm -f ${CAP}
rm -f ${SOCK}
rm -f ${CONF}
