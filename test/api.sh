#!/bin/sh
# shellcheck disable=SC1090
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
setup

export MSG="no-openlog-apitest"


##############################################################################
print "Phase 1 - simple syslog(), no openlog()"
./api
grep "api: ${MSG}" "${LOG}"


##############################################################################
print "Phase 2 - syslog() with openlog() & custom facility"
cat <<EOF >"${CONFD}/console.conf"
console.*	-${LOGCONS}
EOF
reload

./api -i foo
grep "foo: ${MSG}" "${LOGCONS}"


##############################################################################
print "Phase 3 - Verify setlogmask()"

# 1. Verify default log mask (all)
./api -i xyzzy
grep "xyzzy: ${MSG}" "${LOGCONS}" || FAIL "Default logmask filtering broken"
echo "Filtering w/ default logmask works fine"

# 2. Verify setlogmask()
./api -i bar -l
grep "bar: ${MSG}" "${LOGCONS}" && FAIL "Filtering w/ setlogmask() broken"
echo "Filtering w/ setlogmask() works fine"


##############################################################################
print "Phase 4 - Verify RFC5424 API with syslogp()"
cat <<EOF >"${CONFD}/v1.conf"
ftp.*		-${LOGV1}	;RFC5424
EOF
reload

./api -i troglobit -p
sleep 2
grep "troglobit - MSGID - ${MSG}" "${LOGV1}" || (echo "== ${LOGV1}"; tail -10 "${LOGV1}"; echo "== ${LOG}"; tail -10 "${LOG}"; cat "${CONFD}/v1.conf"; FAIL "Cannot find troglobit")


##############################################################################
print "Phase 5 - Verify RFC5424 API with logger(1)"
../src/logger -p ftp.notice -u "${SOCK}" -m "MSDSD" -d '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]' "waldo"
sleep 2
grep "exampleSDID@32473" "${LOGV1}" || (echo "== ${LOGV1}"; tail -10  "${LOGV1}"; FAIL "Cannot find exampleSDID@32473")


##############################################################################
OK
