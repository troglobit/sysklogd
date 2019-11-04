#!/bin/sh
set -e
. ${srcdir}/test.rc

export MSG="no-openlog-apitest"

echo "= Phase 1 - simple syslog(), no openlog() ==============="
./api
grep "api ${MSG}" ${LOG}

echo "= Phase 2 - syslog() with openlog() & custom facility ==="
cat <<EOF >${CONFD}/bar.conf
console.*	-${LOGCONS}
EOF
kill -HUP `cat ${PID}`
sleep 2

./api -i foo
grep "foo ${MSG}" ${LOGCONS}

echo "= Phase 3 - Verify setlogmask() filters out LOG_INFO ===="
./api -i xyzzy -l
grep "xyzzy ${MSG}" ${LOGCONS} || true

echo "= Phase 4 - Verify RFC5424 API with syslogp() ==========="
cat <<EOF >${CONFD}/v1.conf
ftp.*		-${LOGV1}	;RFC5424
EOF
kill -HUP `cat ${PID}`
sleep 2

./api -i troglobit -p
grep "troglobit - MSGID - ${MSG}" ${LOGV1}

