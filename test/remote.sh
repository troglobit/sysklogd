#!/bin/sh
set -x
. ./test.rc

MSG="kilroy"

tshark -Qni lo -w ${CAP} port ${PORT} 2>/dev/null &
#tcpdump -qlni lo -w ${CAP} port ${PORT} 2>/dev/null &
PID="$!"
sleep 1

echo "Hej"
../src/logger -u ${SOCK} ${MSG}

echo "Nej"
sleep 1
kill -TERM ${PID}
wait ${PID}

tshark -d udp.port==${PORT},syslog -r ${CAP} | grep ${MSG}
rm ${CAP}

