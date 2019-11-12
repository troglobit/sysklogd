#!/bin/sh
set -ex
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

MSG="kilroy"

# Start collector in background, note: might need sudo!
#tshark -Qni lo -w ${CAP} port ${PORT} &
tshark -Qni lo -w ${CAP} port 514 &
PID="$!"

# Wait for tshark to start up properly
sleep 2

../src/logger -u ${SOCK} ${MSG}

# Wait for any OS delays, in particular on Travis
sleep 2

# Stop tshark collector
kill -TERM ${PID}
wait ${PID}

# Analyze content, should have $MSG now ...
#tshark -d udp.port==${PORT},syslog -r ${CAP} | grep ${MSG}
tshark -r ${CAP} | grep ${MSG}
rm ${CAP}

