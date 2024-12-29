#!/bin/sh
. "${srcdir:-.}/lib.sh"

MSG1="notrotall-1"
MSG2="notrotall-2"
MSG3="notrotall-3"

NOT=${DIR}/${NM}-1.sh
STP=${DIR}/${NM}-1.stamp

check_deps()
{
    [ -x ../src/logger ]             || SKIP 'logger missing'
    command -v zgrep >/dev/null 2>&1 || SKIP 'zgrep(1) missing'
}

# shellcheck disable=SC2059
setup_notifier()
{
    printf "#!/bin/sh -\necho script 1: \$* >>${STP}\n" > "${NOT}"
    chmod 0755 "${NOT}"
}

setup_syslogd()
{
    cat <<-EOF > "${CONFD}/rotate_all.conf"
	notify ${NOT}
	*.*       -${LOG}    ;rotate=10k:2,RFC5424
	*.*       -${LOG}X   ;rotate=10k:2,RFC5424
	EOF
    setup -m0
}

log_rotate()
{
    rm -f  "$STP"
    logger "$1"

    rotate
}

check_rotate()
{
    NUM=$1; [ "$NUM" -gt 0 ] && NUM=$NUM.gz
    MSG=$2

    test -f "${LOG}.$NUM" && test -f "${LOG}X.$NUM" \
	&& zgrep -H "$MSG" "${LOG}.$NUM" \
	&& zgrep -H "$MSG" "${LOG}X.$NUM"
}

check_notifier()
{
    test -f "$STP" && grep "script 1" "$STP" \
	&& grep -H "$LOG"    "$STP" \
	&& grep -H "${LOG}X" "$STP"
}

run_step "Check dependencies (logger + zgrep)" check_deps
run_step "Create notifier script"              setup_notifier
run_step "Set up syslogd with notifier"        setup_syslogd

run_step "Rotate and log $MSG1"                log_rotate     "$MSG1"
run_step "Check first rotation for $MSG1"      check_rotate 0 "$MSG1"
run_step "Check notifier"                      check_notifier

run_step "Rotate and log $MSG2"                log_rotate     "$MSG2"
run_step "Check first rotation for $MSG2"      check_rotate 0 "$MSG2"
run_step "Check second rotation for $MSG1"     check_rotate 1 "$MSG1"
run_step "Check notifier"                      check_notifier

run_step "Rotate and log $MSG3"                log_rotate     "$MSG3"
run_step "Check first rotation for $MSG3"      check_rotate 0 "$MSG3"
run_step "Check second rotation for $MSG2"     check_rotate 1 "$MSG2"
run_step "Check third rotation for $MSG1"      check_rotate 2 "$MSG1"
run_step "Check notifier"                      check_notifier
