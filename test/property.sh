#!/bin/sh
# Verify property based filtering
. "${srcdir:-.}/lib.sh"

MSG1="Failed password for root from 200.72.41.31 port 40992 ssh2"
MSG2="error: PAM: authentication error for illegal user amanda from 60.28.42.205"
MSG3="pam_unix\(cron:session\): session opened for user root\(uid=0\) by root\(uid=0\)"

LOGDIR="$DIR/log"
SYSLOG="${LOGDIR}/syslog"
MSGLOG="${LOGDIR}/messages"
ERRLOG="${LOGDIR}/auth-err.log"
BANLOG="${LOGDIR}/ban.log"

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
	EOF
    setup -m0
}

verify_log()
{
    tag="$1"; shift
    log="$1"; shift
    msg="$*"

    logger -i -t "$tag" "$msg"
    grep "$msg" "$log"
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
run_step "Verify auth. error go to syslog as well" check_log         "$SYSLOG" "$MSG2"

run_step "Verify regex matching to ban.log"        verify_log "sshd" "$BANLOG" "$MSG1"
