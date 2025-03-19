#!/bin/sh
# Verify log filtering based on ident/tag for both RFC3154 (BSD)
# and RFC5424 formatted log messages sent to syslogd.  A logged
# message can also contain a [PID], so the combinations of various
# tags + pid are also covered.
#
# Regression test for issue #102.
#
. "${srcdir:-.}/lib.sh"

TG1=pimd
TG2=mrouted
TG3=in.tftpd
MSG="Multicast, a perfect weapon for an imperfect time."
UNX="In UNIX we trust"
DOT="We bring 512 byte block gifts"

LOGDIR="$DIR/log"
SYSLOG="${LOGDIR}/syslog"
TG1LOG="${LOGDIR}/$TG1.log"
TG2LOG="${LOGDIR}/$TG2.log"
TG3LOG="${LOGDIR}/$TG3.log"

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
	#!$TG3
	*.*		$TG3LOG
	EOF
    setup -m0
}

# Verify both RFC3164 (BSD) log format and RFC5424, because
# they have different format parsers in syslogd.  Generates
# three additional variants of the given log message: rev,
# rot13, and alphabetically sorted.
verify_tag()
{
    tag="$1"; shift
    log="$1"; shift
    msg="$*"
    rev=$(echo "$msg" | rev)
    rot=$(echo "$msg" | tr 'a-zA-Z' 'n-za-mN-ZA-M')
    bin=$(echo "$msg" | sed 's/./&\n/g' | sort | tr -d '\n')

    # BSD log format (with -b)
    logger -b -ip user.debug -t "$tag" "$msg"
    verify_log "$log" "$msg" | grep "$tag" || return 1

    # RFC5424 (default)
    logger -ip user.debug -t "$tag" "$rev"
    verify_log "$log" "$rev" | grep "$tag" || return 1

    # BSD without -p flag
    logger -b -i -t "$tag" "$rot"
    verify_log "$log" "$rot" | grep "$tag" || return 1

    # RFC5424 without -p flag
    logger -i -t "$tag" "$bin"
    verify_log "$log" "$bin" | grep "$tag" || return 1
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
run_step "Verify basic tag based filtering (3)"    verify_tag "$TG3" "$TG3LOG" "$DOT"
run_step "Verify not in syslog"                    verify_not        "$SYSLOG" "$MSG"

run_step "Verify unfiltered tag logging"           verify_tag "foo"  "$SYSLOG" "$UNX"
run_step "Verify unfiltered message in syslog"     verify_log        "$SYSLOG" "$UNX"
run_step "Verify unfiltered message not filtered"  verify_not        "$TG1LOG" "$UNX"
