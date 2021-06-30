#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

mkdir -p ${CONFD}
cat <<EOF > ${CONF}
# Nothing here yo
include ${CONFD}/*.conf
EOF

mkdir -p ${CONFD2}
cat <<EOF > ${CONF2}
# Nothing here yo
include ${CONFD2}/*.conf
EOF

cat <<EOF > ${CONFD}/foo.conf
# Local log file, avoid sync to disk
*.*	-${LOG}
EOF

cat <<EOF > ${CONFD}/bar.conf
# For remote logging
*.*	@127.0.0.2
EOF

../src/syslogd -m1 -b :${PORT} -d -sF -f ${CONF} -p ${SOCK} -p ${ALTSOCK} -C ${CACHE} -P ${PID} &

sleep 2
kill -USR1 `cat ${PID}`
sleep 1
