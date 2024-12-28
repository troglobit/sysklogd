#!/bin/sh
# shellcheck disable=SC1090
if [ -z "${srcdir}" ]; then
    srcdir=.
fi
. "${srcdir}/lib.sh"


verify_plain()
{
    MSG="foobar"
    logger "${MSG}"
    grep ${MSG} "${LOG}"
}

verify_alt()
{
    MSG="xyzzy"
    logger "${ALTSOCK}" ${MSG}
    grep ${MSG} "${LOG}"
}

run_step "Set up local syslog daemon" setup -m0
run_step "Verify basic logging"       verify_plain
run_step "Verify alternate socket"    verify_alt
