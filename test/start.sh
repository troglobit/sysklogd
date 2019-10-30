#!/bin/sh
. ./test.rc

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi

cat <<EOF > ${CONF}
*.*	-${LOG}
*.*	@127.0.0.2
EOF

../src/syslogd -b :${PORT} -d -n -f ${CONF} -p ${SOCK} &
echo "$!" > ${PID}

sleep 1
