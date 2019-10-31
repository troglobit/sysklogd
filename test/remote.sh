#!/bin/sh
set -ex
. ./test.rc

MSG="kilroy"

tshark -Qni lo -w ${CAP} port ${PORT} 2>/dev/null &
#tcpdump -qlni lo -w ${CAP} port ${PORT} 2>/dev/null &
PID="$!"
sleep 5

../src/logger -u ${SOCK} ${MSG}

sleep 5
kill -TERM ${PID}
wait ${PID}

tshark -d udp.port==${PORT},syslog -r ${CAP} | grep ${MSG}
rm ${CAP}

