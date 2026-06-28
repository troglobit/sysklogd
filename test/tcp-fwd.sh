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
MSG_V6="tcp6 family test message"
MSG_V4="tcp4 family test message"

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
    tenacious 5 grep "fwd - NTP123 - ${MSG}" "${LOG2}"
}

verify_msg_url()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG2}"
    tenacious 5 grep "fwd - NTP123 - ${MSG2}" "${LOG2}"
}

# Send directly from logger to the receiver's TCP listener, bypassing
# the sender syslogd entirely.
verify_direct_tcp()
{
    [ -x ../src/logger ] || SKIP 'logger missing'

    ../src/logger -h "tcp://[::1]:${PORT2}" -t fwd -p ntp.notice "${MSG3}"
    tenacious 5 grep "${MSG3}" "${LOG2}"
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

# Force IPv6 via tcp6://; the receiver listens on [::1] so this arrives.
verify_family6()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*		/dev/null
	ntp.*		tcp6://localhost:${PORT2}	;RFC5424
	EOF
    reload
    sleep 1
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG_V6}"
    tenacious 5 grep "${MSG_V6}" "${LOG2}"
}

# Force IPv4 via tcp4://; the receiver is IPv6-only, so this must NOT
# arrive.  On a build that ignores the 4 selector the resolver falls back
# to the [::1] listener and the message is delivered -- this step fails
# then, catching the regression.
verify_family4_blocked()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*		/dev/null
	ntp.*		tcp4://localhost:${PORT2}	;RFC5424
	EOF
    reload
    sleep 1
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG_V4}"
    sleep 2
    grep "${MSG_V4}" "${LOG2}" && return 1
    return 0
}

run_step "Set up receiver syslogd with TCP listener"            setup_receiver_tcp
run_step "Set up sender syslogd with @@ TCP forwarding"         setup_sender
run_step "Verify TCP forward of message using @@ syntax"        verify_msg
run_step "Reconfigure sender to use tcp:// URL syntax"          setup_sender_url
run_step "Verify TCP forward of message using tcp:// syntax"    verify_msg_url
run_step "Verify direct logger TCP send to syslogd listener"    verify_direct_tcp
run_step "Verify logger -V reports TCP connection established"   verify_verbose_tcp
run_step "Verify tcp6:// forces IPv6 delivery"                  verify_family6
run_step "Verify tcp4:// forces IPv4 (blocked, receiver is v6)"  verify_family4_blocked
