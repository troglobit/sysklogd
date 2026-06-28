#!/bin/sh
# Verify the ;pri action option, which makes syslogd print the message
# priority code in the log line, in the format in use (RFC3164/RFC5424).
# A user.notice message has priority <13> (facility 1 * 8 + severity 5).
#
. "${srcdir:-.}/lib.sh"

LOGDIR="$DIR/log"
PRILOG="${LOGDIR}/pri.log"
PLAINLOG="${LOGDIR}/plain.log"
MSG="priority printing test $$"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	*.*		-${PRILOG}	;pri
	*.*		-${PLAINLOG}
	EOF
    setup -m0
}

# With ;pri the line carries the <13> priority code
verify_pri()
{
    logger -p user.notice -t prit "${MSG}"
    tenacious 5 grep "<13>.*prit: ${MSG}" "${PRILOG}"
}

# The same message must also reach the plain log ...
verify_plain()
{
    tenacious 5 grep "prit: ${MSG}" "${PLAINLOG}"
}

# ... but there without the <13> priority code
verify_plain_no_pri()
{
    grep "<13>" "${PLAINLOG}" && return 1
    return 0
}

run_step "Set up syslogd with a ;pri action"  setup_syslogd
run_step "Verify priority printed with ;pri"  verify_pri
run_step "Verify message reached plain log"   verify_plain
run_step "Verify no priority without ;pri"    verify_plain_no_pri
