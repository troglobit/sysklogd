#!/bin/sh
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
setup

MSG="kilroy"

# Start collector in background, note: might need sudo!
#tshark -Qni lo -w ${CAP} port ${PORT} &
tshark -Qni lo -w ${CAP} port 514 &
TPID="$!"
echo "$TPID" >> "$DIR/PIDs"

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
tshark -r ${CAP} | grep ${MSG} || FAIL "Cannot find: ${MSG}"
rm ${CAP}
