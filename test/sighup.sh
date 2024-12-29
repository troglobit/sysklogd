#!/bin/sh
# Verify syslogd can survive a few SIGHUP's
# shellcheck disable=SC1090
. "${srcdir:-.}/lib.sh"

verify_logging()
{
    MSG="$*"
    logger "${MSG}"
    grep "${MSG}" "${LOG}"
}

rattle_cage()
{
    for _ in $(seq "$1"); do
	dprint "Shaky shaky ..."
	reload
    done
}

run_step "Set up local syslog daemon" setup -m0
run_step "Verify before shakeup"      verify_logging "Diving in the Sky"
run_step "Shake it up mister ..."     rattle_cage 5
run_step "Verify after shakeup"       verify_logging "Summerdream"
