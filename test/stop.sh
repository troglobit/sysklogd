#!/bin/sh -e

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

if [ -e ${PID} ]; then
    echo "Killing 1st syslogd, PID:`cat ${PID}` ..."
    kill `cat ${PID}`
fi

if [ -e ${PID2} ]; then
    echo "Killing 2nd syslogd, PID:`cat ${PID2}` ..."
    kill `cat ${PID2}`
fi

rm -f ${LOG}
rm -f ${LOGV1}
rm -f ${LOG2}
rm -f ${LOGCONS}
rm -f ${PID}
rm -f ${PID2}
rm -f ${CAP}
rm -f ${SOCK}
rm -f ${CONF}
rm -f ${CONF2}
rm -rf ${CONFD}
rm -rf ${CONFD2}
