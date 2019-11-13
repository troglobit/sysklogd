#!/bin/sh
set -ex
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

export MSG="no-openlog-apitest"

echo "= Phase 1 - simple syslog(), no openlog() ==============="
./api
grep "api: ${MSG}" ${LOG}

echo "= Phase 2 - syslog() with openlog() & custom facility ==="
cat <<EOF >${CONFD}/console.conf
console.*	-${LOGCONS}
EOF
kill -HUP `cat ${PID}`
sleep 2

./api -i foo
grep "foo: ${MSG}" ${LOGCONS}

echo "= Phase 3 - Verify setlogmask() filters out LOG_INFO ===="
./api -i xyzzy -l
grep "xyzzy: ${MSG}" ${LOGCONS} || true

echo "= Phase 4 - Verify RFC5424 API with syslogp() ==========="
cat <<EOF >${CONFD}/v1.conf
ftp.*		-${LOGV1}	;RFC5424
EOF
kill -HUP `cat ${PID}`
sleep 2

./api -i troglobit -p
sleep 2
ps fax |grep -A2 syslogd
grep "troglobit - MSGID - ${MSG}" ${LOGV1} || (echo "== ${LOGV1}"; tail -10  ${LOGV1}; echo "== ${LOG}"; tail -10  ${LOG}; cat ${CONFD}/v1.conf; false)

echo "= Phase 4 - Verify RFC5424 API with logger(1) ==========="
../src/logger -p ftp.notice -u ${SOCK} -m "MSDSD" -d '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]' "waldo"
sleep 2
grep "exampleSDID@32473" ${LOGV1} || (echo "== ${LOGV1}"; tail -10  ${LOGV1}; false)

