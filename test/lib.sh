#!/bin/sh

# Test name, used everywhere as /tmp/sysklogd/$NM/foo
NM=$(basename "$0" .sh)
DIR=/tmp/sysklogd/$NM

FN=syslog-test
FN2=syslog-test2
LOG=$DIR/${FN}.log
LOG2=$DIR/${FN2}.log
LOGV1=$DIR/${FN}-v1.log
LOGCONS=$DIR/${FN}-cons.log
PID=$DIR/${FN}.pid
PID2=$DIR/${FN2}.pid
CAP=$DIR/${FN}.pcapng
CACHE=$DIR/${FN}.cache
CACHE2=$DIR/${FN2}.cache
CONF=$DIR/${FN}.conf
CONF2=$DIR/${FN2}.conf
CONFD=$DIR/${FN}.d
CONFD2=$DIR/${FN2}.d
SOCK=$DIR/${FN}.sock
SOCK2=$DIR/${FN2}.sock
ALTSOCK=$DIR/${FN}-alt.sock
PORT=5514
PORT2=5555

export SYSLOG_UNIX_PATH=${SOCK}

# Print heading for test phases
print()
{
    printf "\e[7m>> %-76s\e[0m\n" "$1"
}

dprint()
{
    printf "\e[2m%-76s\e[0m\n" "$1"
}

SKIP()
{
    print "TEST: SKIP"
    [ $# -gt 0 ] && echo "$*"
    exit 77
}

FAIL()
{
    print "TEST: FAIL"
    [ $# -gt 0 ] && echo "$*"
    exit 99
}

OK()
{
    print "TEST: OK"
    [ $# -gt 0 ] && echo "$*"
    exit 0
}

# shellcheck disable=SC2068,SC2086
tenacious()
{
    timeout=$1
    shift

    while [ $timeout -gt 0 ]; do
	$@ && return
	timeout=$((timeout - 1))
    done

    FAIL "Timeed out $*"
}

cap_start()
{
	tshark -Qni lo -w "${CAP}" port 514 2>/dev/null &
	TPID="$!"
	echo "$TPID" >> "$DIR/PIDs"
	sleep 1
}

cap_stop()
{
	sleep 1
	kill -TERM ${TPID}
	wait ${TPID}
}

cap_dump()
{
	tshark -r "${CAP}" 2>/dev/null
}

cap_find()
{
	cap_dump | grep "$@"
}

logger()
{
	[ -x ../src/logger ] || SKIP 'logger missing'

	sock="${SOCK}"
	if [ $# -gt 1 ] && [ -f "$1" ]; then
		sock="$1"
		shift
	fi

	if [ -f "$sock" ]; then
		../src/logger -u "$sock" "$@"
	else
		../src/logger "$@"
	fi
}

# shellcheck disable=SC2046,SC2086
do_setup()
{
    order=$1
    pidfn=$2
    shift 2
    opts="$*"

    ip link set lo up

    print "Starting $order syslogd ..."
    if [ -z "$VALGRIND" ]; then
	    ../src/syslogd -dKF ${opts} &
    else
	    ${VALGRIND} ../src/syslogd -KF ${opts} &
    fi

    sleep 2
    [ -f "${pidfn}" ] || FAIL "Failed starting $order syslogd"
    cat "${pidfn}" >> "$DIR/PIDs"

    # Enable debugging ...
    if [ -z "$VALGRIND" ]; then
	    kill -USR1 $(cat "${pidfn}")
    fi

    sleep 1
}

# set up and start primary syslogd
setup()
{
    if [ ! -f "${CONF}" ]; then
	cat <<-EOF > "${CONF}"
		include ${CONFD}/*.conf
		EOF

	cat <<-EOF > "${CONFD}/foo.conf"
		# Local log file, avoid sync to disk
		*.* -${LOG}
		EOF

	cat <<-EOF > "${CONFD}/bar.conf"
		# For remote logging
		*.* @127.0.0.2
		*.* @127.0.0.2:${PORT2}	;RFC3164
		EOF
    fi

    do_setup "primary" "${PID}" "$*" -b ":${PORT}" -f "${CONF}" -p "${SOCK}" \
	     -p "${ALTSOCK}" -C "${CACHE}" -P "${PID}"
}

# set up and start second syslogd, e.g., for remote.sh
setup2()
{
    cat <<-EOF > "${CONF2}"
	include ${CONFD2}/*.conf
	EOF

    do_setup "secondary" "${PID2}" "$*" -f "${CONF2}" -p "${SOCK2}" \
	     -C "${CACHE2}" -P "${PID2}"
}

is_running()
{
	kill -0 $(cat "$PID")
}

do_reload()
{
    # shellcheck disable=SC2046
    kill -HUP $(cat "$1")
    sleep 1
}

reload()
{
    do_reload "${PID}"
}

reload2()
{
    do_reload "${PID2}"
}

# Stop all lingering collectors and other tools
kill_pids()
{
    # shellcheck disable=SC2162
    if [ -f "$DIR/PIDs" ]; then
	while read ln; do kill "$ln" 2>/dev/null; done < "$DIR/PIDs"
	rm "$DIR/PIDs"
    fi
}

teardown()
{
    kill_pids
    sleep 1

    rm -f ${LOG}
    rm -f ${LOGV1}
    rm -f ${LOG2}
    rm -f ${LOGCONS}
    rm -f ${PID}
    rm -f ${PID2}
    rm -f ${CAP}
    rm -f ${SOCK}
    rm -f ${CACHE}
    rm -f ${CACHE2}
    rm -f ${CONF}
    rm -f ${CONF2}
    rm -rf ${CONFD}
    rm -rf ${CONFD2}
}

signal()
{
    echo
    if [ "$1" != "EXIT" ]; then
	print "Got signal, cleaning up"
    fi
    teardown
}

# props to https://stackoverflow.com/a/2183063/1708249
trapit()
{
    func="$1" ; shift
    for sig ; do
        trap '$func $sig' "$sig"
    done
}

# Runs once when including lib.sh
mkdir -p "${CONFD}"
mkdir -p "${CONFD2}"
touch "$DIR/PIDs"
trapit signal INT TERM QUIT EXIT
