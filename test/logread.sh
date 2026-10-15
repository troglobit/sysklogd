#!/bin/sh
# Verify the in-memory log buffer (membuf) and the logread(1) client:
# messages are captured in the ring, served over the control socket on
# 'dump', filtered with -e, streamed with -f, and the socket is never
# world-accessible.
#
. "${srcdir:-.}/lib.sh"

MBSOCK="$DIR/membuf.sock"
MSG="logread membuf test $$"

logread()
{
    [ -x ../src/logread ] || SKIP 'logread missing'
    ../src/logread -u "${MBSOCK}" "$@"
}

setup_syslogd()
{
    cat <<-EOF >"${CONF}"
	membuf ${MBSOCK} 64k
	*.* -${LOG}
	EOF
    setup
    tenacious 5 test -S "${MBSOCK}"
}

# logread without -f dumps the backlog; poll since syslogd drains async
dump_has()
{
    logread | grep -q "$1"
}

# The socket must be owned by root and carry no access bits for "other"
verify_socket_perms()
{
    perms=$(stat -c '%A' "${MBSOCK}")
    owner=$(stat -c '%U' "${MBSOCK}")

    dprint "socket: ${perms} ${owner}"
    [ "${owner}" = "root" ] || return 1
    case "${perms}" in
	*---) return 0 ;;	# world triad has no permissions
	*)    return 1 ;;
    esac
}

verify_dump()
{
    logger -p user.notice -t lr "${MSG}"
    tenacious 5 dump_has "${MSG}"
}

# -e PATTERN only shows matching lines
verify_filter()
{
    logger -p user.notice -t lr "needle ${MSG}"
    logger -p user.notice -t lr "haystack other line"
    tenacious 5 dump_has "needle ${MSG}"
    logread -e needle | grep -q haystack && return 1
    return 0
}

# -f streams new messages live
verify_follow()
{
    logread -f >"$DIR/follow.out" 2>/dev/null &
    fpid=$!
    echo "$fpid" >> "$DIR/PIDs"
    sleep 1

    logger -p user.notice -t lr "followed ${MSG}"
    tenacious 5 grep "followed ${MSG}" "$DIR/follow.out"
    kill "$fpid" 2>/dev/null
}

# A follow client that disconnects must not take syslogd down (SIGPIPE);
# keep logging after the client is gone and confirm the daemon survives.
verify_survives_client_gone()
{
    logread -f >/dev/null 2>&1 &
    fpid=$!
    sleep 1
    kill -9 "$fpid" 2>/dev/null

    # Fan out several messages to the now-dead client's socket
    for i in 1 2 3 4 5; do
	logger -p user.notice -t lr "after gone ${MSG} $i"
    done
    tenacious 5 grep "after gone ${MSG} 5" "$LOG"
    is_running
}

run_step "Set up syslogd with membuf"             setup_syslogd
run_step "Verify control socket not world-readable" verify_socket_perms
run_step "Verify logread dumps captured messages"  verify_dump
run_step "Verify logread -e filters output"        verify_filter
run_step "Verify logread -f follows live messages" verify_follow
run_step "Verify syslogd survives client disconnect" verify_survives_client_gone
