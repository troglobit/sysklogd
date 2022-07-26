#!/bin/sh
# Verify that the sending to a remote IP:PORT works, note not receiving,
# there's a test fwd.sh that verifies that.
#
# Also, instead of "sleep 3" after starting thsark, below, we take the
# opportunity to perform a regression test of SIGHUP:ing syslogd.
#
# shellcheck disable=SC1090
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
setup

export MSG="kilroy"

# Only needed for verifying correct RFC3164 parsing
cat <<-EOF >"${CONFD2}/50-default.conf"
	*.*	${LOG2}
	EOF

setup2 -m0 -a 127.0.0.2:* -b ":${PORT2}"

print "TEST: Starting"

# Start collector in background, note: might need sudo!
#tshark -Qni lo -w ${CAP} port ${PORT} &
tshark -Qni lo -w "${CAP}" port 514 2>/dev/null &
TPID="$!"
echo "$TPID" >> "$DIR/PIDs"

# While Waiting for tshark to start up properly we take the opportunity
# to verify syslogd survives a few SIGHUP's.  The pe_sock[] has max 16
# elements, which should get closed and refilled on SIGHUP.
for i in $(seq 1 20); do
	reload
done

# Now send the message and see if we sent it ...
logger ${MSG}

# Wait for any OS delays, in particular on Travis
sleep 1

# Stop tshark collector
kill -TERM ${TPID}
wait ${TPID}

# Analyze content, should have $MSG now ...
#tshark -d udp.port==${PORT},syslog -r ${CAP} | grep ${MSG}
tshark -r "${CAP}" 2>/dev/null | grep "${MSG}" || FAIL "Cannot find: ${MSG}"

OK
