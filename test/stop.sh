#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

if [ -e ${PID} ]; then
    echo "Killing `cat ${PID}` ..."
    kill `cat ${PID}`
fi

rm -f ${LOG}
rm -f ${LOGV1}
rm -f ${LOGCONS}
rm -f ${PID}
rm -f ${CAP}
rm -f ${SOCK}
rm -f ${CONF}
rm -rf ${CONFD}
rm -rf ${CONFD2}
