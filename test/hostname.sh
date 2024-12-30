#!/bin/sh
# Verify hstname based filtering.
#set -x
. "${srcdir:-.}/lib.sh"

HST1="finlandia"
HST2="sibelius"
MSG1="Be Still, My Soul"
MSG2="Oi Suomi, katso"
TEXT="Ack Värmeland, du sköna"

LOGDIR="$DIR/log"
SYSLOG="${LOGDIR}/syslog"
HST1LG="${LOGDIR}/$HST1.log"
HST2LG="${LOGDIR}/$HST2.log"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	#-$HST1,$HST2
	*.*		-$SYSLOG
	#+$HST1
	*.*		$HST1LG
	#+$HST2
	*.*		$HST2LG
	EOF
    setup -m0 -8
}

verify_hst()
{
    hst="$1"; shift
    log="$1"; shift
    msg="$*"

    if [ "$hst" = "@" ]; then
	pri=user.panic
	usr="$LOGNAME"
    else
	pri=daemon.notice
	usr="jean"
    fi

    logger -H "$hst" -t "$usr" -p $pri "$msg"
    grep   -H "$msg" "$log"
}

verify_log()
{
    log="$1"; shift
    msg="$*"

    grep -H "$msg" "$log"
}

verify_not()
{
    verify_log "$@" || return 0
}

run_step "Set up property based filtering syslogd" setup_syslogd
run_step "Verify basic tag based filtering (1)"    verify_hst "$HST1" "$HST1LG" "$MSG1"
run_step "Verify basic tag based filtering (2)"    verify_hst "$HST2" "$HST2LG" "$MSG2"
run_step "Verify not in syslog"                    verify_not         "$SYSLOG" "$MSG1"

run_step "Verify unfiltered host logging"          verify_hst "@"     "$SYSLOG" "$TEXT"
run_step "Verify unfiltered message in syslog"     verify_log         "$SYSLOG" "$TEXT"
run_step "Verify unfiltered message not filtered"  verify_not         "$HST1LG" "$TEXT"
