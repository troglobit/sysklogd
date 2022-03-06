#!/bin/sh
# Test FWD between two syslogd, second binds 127.0.0.2:5555
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

../src/logger -t fwd -p ntp.notice -u "${SOCK}" -m "NTP123" "${MSG}"
sleep 3
grep "fwd - NTP123 - ${MSG}" "${LOG2}" || FAIL "Nothing forwarded."

OK
