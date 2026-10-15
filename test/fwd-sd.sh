#!/bin/sh
# Verify the sd= action option, which appends a structured data element
# to every RFC5424 message logged by that action.  Any structured data
# already in the message must be kept, and the local RFC3164 log must
# not be affected.
. "${srcdir:-.}/lib.sh"

SD='[device@32473 name="kilroy" note="1;2,3"]'
MSG="Kilroy was here"
MSG2="Kilroy was here too"

setup_sender()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*		/dev/null
	user.*		@[::1]:${PORT2}	;RFC5424,sd=${SD}
	EOF
    setup -m0
}

setup_receiver()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	kern.*		/dev/null
	*.*;kern.none	${LOG2}			;RFC5424
	EOF
    setup2 -m0 -a "[::1]:*" -b ":${PORT2}"
}

verify_sd()
{
    logger -t fwdsd -p user.notice "${MSG}"
    tenacious 5 grep -qF "fwdsd - - ${SD} ${MSG}" "${LOG2}"
}

verify_append()
{
    logger -t fwdsd -p user.notice -d '[exampleSDID@32473 iut="3"]' "${MSG2}"
    tenacious 5 grep -qF "fwdsd - - [exampleSDID@32473 iut=\"3\"]${SD} ${MSG2}" "${LOG2}"
}

verify_local()
{
    tenacious 5 grep -q "fwdsd: ${MSG}" "${LOG}"
    grep -qF "${SD}" "${LOG}" && return 1
    return 0
}

run_step "Set up sender with sd= on forwarding action"           setup_sender
run_step "Set up receiver logging in RFC5424 format"            setup_receiver
run_step "Verify forwarded message carries the sd= element"     verify_sd
run_step "Verify sd= element is appended to existing SD"        verify_append
run_step "Verify local RFC3164 log is unaffected"               verify_local
