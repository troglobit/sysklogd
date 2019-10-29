#!/bin/sh
. ./test.rc

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi

cat <<EOF > ${CFG} 
*.*	-${LOG}
*.*	@192.168.1.1
EOF

../src/syslogd -d -n -f ${CFG} -p ${SCK} -P ${PID} &

sleep 1
