#!/bin/sh
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

mkdir -p ${CONFD}
cat <<EOF > ${CONF}
# Match all log messages, store in RC5424 format and rotate every 10 MiB
*.*       -${LOG}    ;rotate=10M:5,RFC5424
EOF

../src/syslogd -m1 -b :${PORT} -d -sF -f ${CONF} -p ${SOCK} -p ${ALTSOCK} >${LOG2} &
echo "$!" > ${PID}

sleep 1
kill -9 ${PID}

grep ';RFC5424,rotate=10000000:5' ${LOG2}
