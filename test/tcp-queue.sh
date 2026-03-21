#!/bin/sh
# Verify per-destination TCP send queue: messages queued during outage
# are flushed automatically on reconnect.
#
# The sender syslogd is configured with a short tcp_suspend_time so the
# test completes in a few seconds rather than 180.
#
. "${srcdir:-.}/lib.sh"

MSG_BASE="tcp-queue-baseline-$$"
MSG_Q1="tcp-queue-outage-1-$$"
MSG_Q2="tcp-queue-outage-2-$$"
MSG_Q3="tcp-queue-outage-3-$$"
MSG_TRIGGER="tcp-queue-trigger-$$"
SUSPEND=4   # must be >= tcp_suspend_time in config below

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
	tcp_suspend_time 3
	EOF
    setup -m0
}

verify_baseline()
{
    logger -t tcp-queue -p ntp.notice "${MSG_BASE}"
    sleep 2
    grep "${MSG_BASE}" "${LOG2}"
}

kill_receiver()
{
    kill "$(cat "${PID2}")"
    # Let the FIN/RST propagate so the sender's socket error state is set
    sleep 1
    # Send a probe message; its send() may appear to succeed (CLOSE_WAIT)
    # or fail immediately (RST already received).  Either way, by the time
    # we inject the real queue messages, the next send() will return an
    # error and syslogd will enter SUSP and start queueing.
    logger -t tcp-queue -p ntp.notice "tcp-queue-probe-$$" || true
    sleep 1
}

inject_during_outage()
{
    logger -t tcp-queue -p ntp.notice "${MSG_Q1}"
    logger -t tcp-queue -p ntp.notice "${MSG_Q2}"
    logger -t tcp-queue -p ntp.notice "${MSG_Q3}"
    sleep 1
}

restart_receiver()
{
    rm -f "${PID2}"
    setup_receiver_tcp
}

trigger_reconnect()
{
    # Wait for the suspension window to expire, then send a message
    # which causes the sender to attempt reconnect and flush the queue.
    sleep $((SUSPEND + 1))
    logger -t tcp-queue -p ntp.notice "${MSG_TRIGGER}"
    sleep 2
}

verify_all_arrived()
{
    grep "${MSG_Q1}"      "${LOG2}"
    grep "${MSG_Q2}"      "${LOG2}"
    grep "${MSG_Q3}"      "${LOG2}"
    grep "${MSG_TRIGGER}" "${LOG2}"
}

run_step "Set up TCP receiver"              setup_receiver_tcp
run_step "Set up TCP sender"                setup_sender
run_step "Verify baseline delivery"         verify_baseline
run_step "Kill receiver (simulate outage)"  kill_receiver
run_step "Send 3 messages during outage"    inject_during_outage
run_step "Restart receiver"                 restart_receiver
run_step "Trigger reconnect and flush"      trigger_reconnect
run_step "Verify all queued msgs arrived"   verify_all_arrived
