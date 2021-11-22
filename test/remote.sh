#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/start.sh

MSG="kilroy"

# Start collector in background, note: might need sudo!
#tshark -Qni lo -w ${CAP} port ${PORT} &
tshark -Qni lo -w ${CAP} port 514 &
TPID="$!"

# Wait for tshark to start up properly
sleep 3

../src/logger -u ${SOCK} ${MSG}

# Wait for any OS delays, in particular on Travis
sleep 1

# Stop tshark collector
kill -TERM ${TPID}
wait ${TPID}

# Analyze content, should have $MSG now ...
#tshark -d udp.port==${PORT},syslog -r ${CAP} | grep ${MSG}
tshark -r ${CAP} | grep ${MSG}
rm ${CAP}

. ./stop.sh
