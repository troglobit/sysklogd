#!/bin/sh
# Verify TCP forwarding between two syslogd instances
#
# Tests both @@ and tcp:// syntax for TCP forwarding, plus direct
# logger-to-syslogd TCP delivery and the logger -V verbose mode.
#
. "${srcdir:-.}/lib.sh"

MSG="tcp fwd test message"
MSG2="tcp fwd url test message"
MSG3="direct logger tcp message"
MSG4="logger verbose tcp message"

setup_receiver()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	kern.*		/dev/null
	*.*;kern.none	${LOG2}			;RFC5424
	EOF
    setup2 -m0 -a "[::1]:*" -b ":${PORT2}"
}

setup_receiver_tcp()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	kern.*		/dev/null
	*.*;kern.none	${LOG2}			;RFC5424
	listen		tcp://[::1]:${PORT2}
	EOF
    setup2 -m0 -a "[::1]:*"
}

setup_sender()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*		/dev/null
	ntp.*		@@[::1]:${PORT2}	;RFC5424
	EOF
    setup -m0
}

setup_sender_url()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*		/dev/null
	ntp.*		tcp://[::1]:${PORT2}	;RFC5424
	EOF
    reload
    sleep 1
}

verify_msg()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG}"
    sleep 3

    grep "fwd - NTP123 - ${MSG}" "${LOG2}"
}

verify_msg_url()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG2}"
    sleep 3

    grep "fwd - NTP123 - ${MSG2}" "${LOG2}"
}

# Send directly from logger to the receiver's TCP listener, bypassing
# the sender syslogd entirely.
verify_direct_tcp()
{
    [ -x ../src/logger ] || SKIP 'logger missing'

    ../src/logger -h "tcp://[::1]:${PORT2}" -t fwd -p ntp.notice "${MSG3}"
    sleep 2

    grep "${MSG3}" "${LOG2}"
}

# Use logger -V (verbose) to confirm that a TCP connection was established.
# -V prints "connected to <host> port <N> (tcp)" on stderr on success.
verify_verbose_tcp()
{
    [ -x ../src/logger ] || SKIP 'logger missing'

    output=$(../src/logger -V -h "tcp://[::1]:${PORT2}" -t fwd -p ntp.notice "${MSG4}" 2>&1)
    echo "${output}"
    echo "${output}" | grep -i "connected"
}

run_step "Set up receiver syslogd with TCP listener"            setup_receiver_tcp
run_step "Set up sender syslogd with @@ TCP forwarding"         setup_sender
run_step "Verify TCP forward of message using @@ syntax"        verify_msg
run_step "Reconfigure sender to use tcp:// URL syntax"          setup_sender_url
run_step "Verify TCP forward of message using tcp:// syntax"    verify_msg_url
run_step "Verify direct logger TCP send to syslogd listener"    verify_direct_tcp
run_step "Verify logger -V reports TCP connection established"   verify_verbose_tcp
