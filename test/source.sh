#!/bin/sh
# Verify :source property filter matches the peer a message was received
# from, not the hostname in the message.  Messages are injected over IPv6,
# IPv4, and the local UNIX socket, each with a bogus hostname.
. "${srcdir:-.}/lib.sh"

HOSTNAME=$(hostname | cut -d. -f1)
MSG6="source-ipv6-needle-$$"
MSG4="source-ipv4-needle-$$"
MSGL="source-local-needle-$$"

LOGDIR="$DIR/log"
ALLLOG="${LOGDIR}/full"
V6LOG="${LOGDIR}/v6.log"
V4LOG="${LOGDIR}/v4.log"
LOCLOG="${LOGDIR}/local.log"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	:source, isequal, "::1"
	*.*		$V6LOG
	:source, isequal, "127.0.0.1"
	*.*		$V4LOG
	:source, isequal, "$HOSTNAME"
	*.*		$LOCLOG
	:*
	*.*		$ALLLOG
	EOF
    # -n: no reverse lookup, so the peer address is matched verbatim
    setup -m0 -n
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

# send LOG HOST MSG [LOGGER OPTS]
send()
{
    log="$1"; host="$2"; msg="$3"; shift 3

    logger "$@" -H "$host" -t src "$msg"
    tenacious 5 grep "$host src: $msg" "$log"
}

run_step "Set up syslogd with :source filters"      setup_syslogd

run_step "Verify IPv6 peer sorted by source"        send "$V6LOG" dut1 "$MSG6" -h "[::1]:${PORT}"
run_step "Verify IPv6 peer not in IPv4 log"         check_not "$V4LOG"  "$MSG6"
run_step "Verify IPv6 peer not in local log"        check_not "$LOCLOG" "$MSG6"

run_step "Verify IPv4 peer sorted by source"        send "$V4LOG" dut2 "$MSG4" -h "127.0.0.1:${PORT}"
run_step "Verify IPv4 peer not in IPv6 log"         check_not "$V6LOG"  "$MSG4"

run_step "Verify local message sorted by source"    send "$LOCLOG" dut3 "$MSGL"
run_step "Verify local message not in IPv6 log"     check_not "$V6LOG"  "$MSGL"
run_step "Verify internal message sorted as local"  check_log "$LOCLOG" "syslogd.*restart"

run_step "Verify IPv6 message in catch-all log"     check_log "$ALLLOG" "$MSG6"
run_step "Verify IPv4 message in catch-all log"     check_log "$ALLLOG" "$MSG4"
run_step "Verify local message in catch-all log"    check_log "$ALLLOG" "$MSGL"
