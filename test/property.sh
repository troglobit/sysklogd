#!/bin/sh
# Verify property based filtering
. "${srcdir:-.}/lib.sh"

MSG1="Failed password for root from 200.72.41.31 port 40992 ssh2"
MSG2="error: PAM: authentication error for illegal user amanda from 60.28.42.205"
MSG3="pam_unix\(cron:session\): session opened for user root\(uid=0\) by root\(uid=0\)"

MSGM="property MULTI needle $$"
MSGN="property plain needle $$"

LOGDIR="$DIR/log"
SYSLOG="${LOGDIR}/syslog"
MSGLOG="${LOGDIR}/messages"
ERRLOG="${LOGDIR}/auth-err.log"
BANLOG="${LOGDIR}/ban.log"
MULTIA="${LOGDIR}/multi-a.log"
MULTIB="${LOGDIR}/multi-b.log"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	*.*		-$SYSLOG
	:msg, !icase_regex, ".*session opened for user.*"
	*.notice	-$MSGLOG
	:msg, icase_contains, "ERROR"
	*.*		$ERRLOG
	:msg, icase_regex, "failed password for .* from .* port .* ssh[123]"
	*.*		$BANLOG
	:msg, contains, "MULTI"
	*.*		$MULTIA
	*.*		$MULTIB
	:*
	EOF
    setup -m0
}

verify_log()
{
    tag="$1"; shift
    log="$1"; shift
    msg="$*"

    logger -i -t "$tag" "$msg"
    tenacious 5 grep "$msg" "$log"
}

check_log()
{
    log="$1"; shift
    msg="$*"

    grep "$msg" "$log"
}

check_not()
{
    check_log "$@" || return 0
}

run_step "Set up property based filtering syslogd" setup_syslogd

run_step "Verify generic msg got to syslog"        verify_log "CRON" "$SYSLOG" "$MSG3"
run_step "Verify generic msg not in msessages"     check_not         "$MSGLOG" "$MSG3"

run_step "Verify auth. error go to auth-err.log"   verify_log "sshd" "$ERRLOG" "$MSG2"
run_step "Verify auth. error go to syslog as well" tenacious 5 check_log "$SYSLOG" "$MSG2"

run_step "Verify regex matching to ban.log"        verify_log "sshd" "$BANLOG" "$MSG1"

# Regression: a :filter block heading more than one rule must apply the
# filter to every rule, not just the first.  prop_filter_compile() used
# to clobber the shared filter buffer, leaving rule 2+ unfiltered.
run_step "Verify multi-rule filter, rule 1 match"  verify_log "m" "$MULTIA" "$MSGM"
run_step "Verify multi-rule filter, rule 2 match"  tenacious 5 check_log "$MULTIB" "$MSGM"
run_step "Send non-matching message to catch-all"  verify_log "m" "$SYSLOG" "$MSGN"
run_step "Verify non-match absent from rule 2"      check_not  "$MULTIB" "$MSGN"
