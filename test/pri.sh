#!/bin/sh
# Verify the ;pri action option and the equivalent NetBSD-style '+' (and
# '+-') destination prefix, which make syslogd print the message priority
# code in the log line.  A user.notice message has priority <13>
# (facility 1 * 8 + severity 5).
#
. "${srcdir:-.}/lib.sh"

LOGDIR="$DIR/log"
PRILOG="${LOGDIR}/pri.log"
PLAINLOG="${LOGDIR}/plain.log"
PLUSLOG="${LOGDIR}/plus.log"
PMLOG="${LOGDIR}/plusminus.log"
MSG="priority printing test $$"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	*.*		-${PRILOG}	;pri
	*.*		-${PLAINLOG}
	*.*		+${PLUSLOG}
	*.*		+-${PMLOG}
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

# The '+' prefix preserves the priority, like ;pri
verify_plus()
{
    tenacious 5 grep "<13>.*prit: ${MSG}" "${PLUSLOG}"
}

# The combined '+-' prefix (preserve priority, no sync) does too
verify_plusminus()
{
    tenacious 5 grep "<13>.*prit: ${MSG}" "${PMLOG}"
}

run_step "Set up syslogd with ;pri and +/+- actions"  setup_syslogd
run_step "Verify priority printed with ;pri"          verify_pri
run_step "Verify message reached plain log"           verify_plain
run_step "Verify no priority without ;pri"            verify_plain_no_pri
run_step "Verify '+' prefix preserves priority"       verify_plus
run_step "Verify '+-' prefix preserves priority"      verify_plusminus
