#!/bin/sh
# Verify stop-processing block prefixes (!! ++ ::)
#
# A block prefixed with :: (propfilter), !! (program), or ++ (hostname)
# stops further rule processing for a matching message.  This test
# exercises all three forms and confirms that non-matching messages
# fall through to subsequent rules as expected.
#
. "${srcdir:-.}/lib.sh"

MSG_STOP="STOPME-needle-7a3f"
MSG_PASS="PASSTHRU-needle-8b2e"
MSG_PROG="PROGSTOP-needle-9c1d"
MSG_OTHER="OTHERPROG-needle-0d4c"

LOGDIR="$DIR/log"
STOPLOG="${LOGDIR}/stop.log"
PROGLOG="${LOGDIR}/prog.log"
CATCHALL="${LOGDIR}/all.log"

# Config layout:
#   1. ::propfilter stop-block  → STOPLOG  (stops; MSG_STOP never reaches CATCHALL)
#   2. !!stopper stop-block     → PROGLOG  (stops; MSG_PROG from "stopper" never reaches CATCHALL)
#   3. !* resets program filter so the catch-all below applies to all programs
#   4. catch-all                → CATCHALL (receives everything not stopped above)
setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	::msg, contains, "${MSG_STOP}"
	*.*		${STOPLOG}
	!!stopper
	*.*		${PROGLOG}
	!*
	*.*		-${CATCHALL}
	EOF
    setup -m0
}

# Send MSG_STOP, expect it in STOPLOG
check_stop_in_stoplog()
{
    logger -t test -p user.notice "${MSG_STOP}"
    sleep 1
    grep "${MSG_STOP}" "${STOPLOG}"
}

# MSG_STOP must NOT appear in CATCHALL (stop-processing worked)
check_stop_not_in_catchall()
{
    grep "${MSG_STOP}" "${CATCHALL}" && return 1
    return 0
}

# Send MSG_PASS (no match for stop filter), expect it in CATCHALL
check_pass_in_catchall()
{
    logger -t test -p user.notice "${MSG_PASS}"
    sleep 1
    grep "${MSG_PASS}" "${CATCHALL}"
}

# MSG_PASS must NOT appear in STOPLOG
check_pass_not_in_stoplog()
{
    grep "${MSG_PASS}" "${STOPLOG}" && return 1
    return 0
}

# Send MSG_PROG from tag "stopper", expect it in PROGLOG (!! stop-block)
check_prog_in_proglog()
{
    logger -t stopper -p user.notice "${MSG_PROG}"
    sleep 1
    grep "${MSG_PROG}" "${PROGLOG}"
}

# MSG_PROG from "stopper" must NOT appear in CATCHALL
check_prog_not_in_catchall()
{
    grep "${MSG_PROG}" "${CATCHALL}" && return 1
    return 0
}

# Send MSG_OTHER from a different tag, expect it in CATCHALL only
check_other_in_catchall()
{
    logger -t otherprog -p user.notice "${MSG_OTHER}"
    sleep 1
    grep "${MSG_OTHER}" "${CATCHALL}"
}

# MSG_OTHER must NOT appear in PROGLOG
check_other_not_in_proglog()
{
    grep "${MSG_OTHER}" "${PROGLOG}" && return 1
    return 0
}

run_step "Set up syslogd with stop-processing rules"          setup_syslogd

run_step "Matched msg (propfilter ::) lands in stop log"      check_stop_in_stoplog
run_step "Matched msg (propfilter ::) absent from catch-all"  check_stop_not_in_catchall
run_step "Non-matched msg reaches catch-all"                  check_pass_in_catchall
run_step "Non-matched msg absent from stop log"               check_pass_not_in_stoplog

run_step "Matched msg (program !!) lands in prog log"         check_prog_in_proglog
run_step "Matched msg (program !!) absent from catch-all"     check_prog_not_in_catchall
run_step "Other-program msg reaches catch-all"                check_other_in_catchall
run_step "Other-program msg absent from prog log"             check_other_not_in_proglog
