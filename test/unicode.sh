#!/bin/sh
# Currently only same as local.sh but with unicode messages
# From https://github.com/troglobit/sysklogd/issues/49
# shellcheck disable=SC1090
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh
setup -8

MSG="öäüÖÄÜß€¢§"
MSG2="…‘’•"

../src/logger -u "${SOCK}" ${MSG}
grep ${MSG} "${LOG}" || FAIL "Cannot find: ${MSG}"

../src/logger -u "${ALTSOCK}" ${MSG2}
grep ${MSG2} "${LOG}" || FAIL "Cannot find: ${MSG2}"

OK
