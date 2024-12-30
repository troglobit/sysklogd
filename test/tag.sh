#!/bin/sh
# Verify property based filtering, including ident/tag.
. "${srcdir:-.}/lib.sh"

TG1=pimd
TG2=mrouted
MSG="Multicast, a perfect weapon for an imperfect time."
UNX="In UNIX we trust"

LOGDIR="$DIR/log"
SYSLOG="${LOGDIR}/syslog"
TG1LOG="${LOGDIR}/$TG1.log"
TG2LOG="${LOGDIR}/$TG2.log"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	#!-$TG1,$TG2
	*.*		-$SYSLOG
	#!$TG1
	*.*		$TG1LOG
	#!$TG2
	*.*		$TG2LOG
	EOF
    setup -m0
}

verify_tag()
{
    tag="$1"; shift
    log="$1"; shift
    msg="$*"

    logger -t "$tag" "$msg"
    grep "$msg" "$log"
}

verify_log()
{
    log="$1"; shift
    msg="$*"

    grep "$msg" "$log"
}

verify_not()
{
    verify_log "$@" || return 0
}

run_step "Set up property based filtering syslogd" setup_syslogd
run_step "Verify basic tag based filtering (1)"    verify_tag "$TG1" "$TG1LOG" "$MSG"
run_step "Verify basic tag based filtering (2)"    verify_tag "$TG2" "$TG2LOG" "$MSG"
run_step "Verify not in syslog"                    verify_not        "$SYSLOG" "$MSG"

run_step "Verify unfiltered tag logging"           verify_tag "foo"  "$SYSLOG" "$UNX"
run_step "Verify unfiltered message in syslog"     verify_log        "$SYSLOG" "$UNX"
run_step "Verify unfiltered message not filtered"  verify_not        "$TG1LOG" "$UNX"
