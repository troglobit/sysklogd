#!/bin/sh
# Test FWD between two syslogd, second binds 127.0.0.2:5555
# shellcheck disable=SC1090

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi

. ${srcdir}/lib.sh
setup -m0

MSG="fwd and allow"

cat <<EOF >"${CONFD}/fwd.conf"
kern.*		/dev/null
ntp.*		@127.0.0.2:${PORT2}	;RFC5424
EOF

reload

cat <<EOF >"${CONFD2}/50-default.conf"
kern.*		/dev/null
*.*;kern.none	${LOG2}			;RFC5424
EOF

setup2 -m0 -a 127.0.0.2:* -b ":${PORT2}"

print "TEST: Starting"

logger -t fwd -p ntp.notice -m "NTP123" "${MSG}"
sleep 3  # Allow message to be received, processed, and forwarded
grep "fwd - NTP123 - ${MSG}" "${LOG2}" || FAIL "Nothing forwarded."

OK
