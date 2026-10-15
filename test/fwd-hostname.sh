#!/bin/sh
# Verify the hostname= action option, which replaces the hostname in
# messages sent to that action, e.g. when forwarding to a remote server.
# The local log file must keep the real hostname.
. "${srcdir:-.}/lib.sh"

NAME="kilroy"
MSG="Kilroy was here"

setup_sender()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*		/dev/null
	user.*		@[::1]:${PORT2}	;RFC5424,hostname=${NAME}
	EOF
    setup -m0
}

setup_receiver()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	kern.*		/dev/null
	*.*;kern.none	${LOG2}			;RFC5424
	EOF
    setup2 -m0 -H -n -a "[::1]:*" -b ":${PORT2}"
}

verify_remote()
{
    logger -t fwdhost -p user.notice "${MSG}"
    tenacious 5 grep -q " ${NAME} fwdhost - - - ${MSG}" "${LOG2}"
}

verify_local()
{
    tenacious 5 grep -q "fwdhost: ${MSG}" "${LOG}"
    grep -q " ${NAME} fwdhost" "${LOG}" && return 1
    return 0
}

run_step "Set up sender with hostname=${NAME} on forwarding action" setup_sender
run_step "Set up receiver keeping the hostname from the message"    setup_receiver
run_step "Verify forwarded message carries ${NAME}"                 verify_remote
run_step "Verify local log keeps the real hostname"                 verify_local
