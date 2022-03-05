#!/bin/sh
# Verify that the sending to a remote IP:PORT works, note not receiving,
# there's a test fwd.sh that verifies that.
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
setup

export MSG="kilroy"

# Only needed for verifying correct RFC3164 parsing
cat <<-EOF >${CONFD2}/50-default.conf
	*.*	${LOG2}
	EOF
../src/syslogd -K -a 127.0.0.2:* -b :${PORT2} -d -F -f ${CONF2} -p ${SOCK2} -m1 -C ${CACHE2} -P ${PID2} &
sleep 3
cat ${PID2} >> "$DIR/PIDs"
kill -USR1 `cat ${PID2}`

# Start collector in background, note: might need sudo!
#tshark -Qni lo -w ${CAP} port ${PORT} &
tshark -Qni lo -w ${CAP} port 514 2>/dev/null &
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
tshark -r ${CAP} 2>/dev/null | grep ${MSG} || FAIL "Cannot find: ${MSG}"
