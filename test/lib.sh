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
STEP=1
PORT=5514
PORT2=5555

export SYSLOG_UNIX_PATH="${SOCK}"

# Print heading for test phases
print()
{
    printf "\e[7m>> %-78s\e[0m\n" "$1"
}

# Dimmed text
dprint()
{
    printf "\e[2m%-78s\e[0m\n" "$1"
}

step()
{
    heading=${1:-}
    if [ -n "$heading" ]; then
	num=$((72 - ${#heading} - 1))
	printf "\n\e[1mStep $STEP ― %s " "$heading"
	STEP=$((STEP + 1))
	printf -- "―%.0s" $(seq 1 $num)
	printf "\e[0m\n"
    else
	printf "\e[1m――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――\e[0m\n"
    fi
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

run_step()
{
    desc=$1
    func=$2
    shift 2

    step "${desc}"
    if eval "${func} $*"; then
	dprint "OK"
    else
        FAIL "${desc} failed."
    fi
}

tenacious()
{
    timeout=$1
    shift

    while [ "$timeout" -gt 0 ]; do
	"$@" && return
	timeout=$((timeout - 1))
	sleep 1
    done

    FAIL "Timed out $*"
}

# Start collector in background, note: might need sudo!
cap_start()
{
    command -v tshark >/dev/null 2>&1 || SKIP 'tshark missing'
    if [ $# -gt 1 ]; then
	iface=$1
	shift
    else
	iface=lo
    fi
    port=${1:-514}

    tshark -Qni "$iface" -w "${CAP}" port "$port" 2>/dev/null &
    TPID="$!"
    echo "$TPID" >> "$DIR/PIDs"
    sleep 1
}

cap_stop()
{
    sleep 1
    kill -TERM "${TPID}"
    wait "${TPID}"
}

# Optional port argument to remap for syslog dissector
cap_dump()
{
    if [ $# -gt 0 ]; then
	data="-d udp.port==$1,syslog"
    fi

    # shellcheck disable=SC2086
    tshark -r "${CAP}" $data -o 'gui.column.format:"N:o","%m","TTL","%Cus:ip.ttl","Source","%us","Destination","%ud","src port","%S","dst port","%D","Info","%i"' 2>/dev/null
}

cap_find()
{
    cap_dump | grep "$@"
}

# Remap traffic on port to syslog
cap_find_port()
{
    port=$1; shift
    cap_dump "$port" | grep "$@"
}

logger()
{
    [ -x ../src/logger ] || SKIP 'logger missing'

    if [ $# -gt 1 ] && [ -S "$1" ]; then
	sock="$1"
	shift
    elif [ $# -eq 1 ]; then
	sock="${SOCK}"
    fi

    if [ -S "$sock" ]; then
	../src/logger -u "$sock" "$@"
    else
	../src/logger "$@"
    fi
}

log_and_find()
{
    [ $# -gt 1 ] && altsock="$1" && shift
    message="$*"

    logger "${altsock}" "$message"
    grep   "$message"   "$LOG"
}

# Helper to poll for a file with a timeout
poll()
{
    file=$1
    timeout=${2:-10} # Default timeout 10 seconds
    start_time=$(date +%s.%N)

    while [ ! -f "$file" ]; do
        sleep 0.1
        current_time=$(date +%s.%N)
        elapsed=$(echo "$current_time - $start_time" | bc)
        if [ "$(echo "$elapsed >= $timeout" | bc)" -eq 1 ]; then
            return 1
        fi
    done

    return 0
}

# shellcheck disable=SC2002
do_setup()
{
    order=$1
    pidfn=$2
    logfn=${2}.log
    shift 2
    opts="$*"

    ip link set lo up

    dprint "Starting $order syslogd ..."
    cmd="../src/syslogd -dKF ${opts}"
    [ -n "$VALGRIND" ] && cmd="${VALGRIND} ${cmd}"

    if [ -z "$DEBUG" ]; then
        $cmd >"$logfn" 2>&1 &
    else
        $cmd &
    fi

    if ! poll "${pidfn}"; then
        FAIL "Failed starting $order syslogd"
    fi
    pid=$(cat "${pidfn}" | tee -a "$DIR/PIDs")
    dprint "Started as PID $pid"

    # Enable debugging ...
    if [ -z "$VALGRIND" ]; then
	dprint "Enabling debugging, sending USR1 to $pid ..."
	kill -USR1 "$pid"
    fi
}

# stand-alone single syslogd
setup0()
{
    addr=$1; shift

    ip link set lo up state up
    ip addr add ::1/128 dev lo 2>/dev/null
    ip link add eth0 type dummy
    ip link set eth0 up state up
    ip addr add "$addr" dev eth0

    do_setup "stand-alone" "${PID}" "$*" -f "${CONF}" -p "${SOCK}" -C "${CACHE}" -P "${PID}"
}

# set up and start primary syslogd
setup()
{
    if [ ! -f "${CONF}" ]; then
	cat <<-EOF > "${CONF}"
		# Local log file, needed by most tests
		*.* -${LOG}
		include ${CONFD}/*.conf
		EOF
    fi

    do_setup "primary" "${PID}" "$*" -H -b ":${PORT}" -f "${CONF}" -p "${SOCK}" \
	     -p "${ALTSOCK}" -C "${CACHE}" -P "${PID}"
}

# set up and start second syslogd, e.g., for remote.sh
setup2()
{
    if [ ! -f "${CONF2}" ]; then
	cat <<-EOF > "${CONF2}"
		include ${CONFD2}/*.conf
		EOF
    fi

    do_setup "secondary" "${PID2}" "$*" -f "${CONF2}" -p "${SOCK2}" \
	     -C "${CACHE2}" -P "${PID2}"
}

is_running()
{
    if [ -f "$PID" ]; then
	kill -0 "$(cat "$PID")"
    else
	false
    fi
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

rotate()
{
    kill -USR2 "$(cat "${PID}")"
    sleep 1
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
    if [ -z "$DEBUG" ]; then
	sleep 1
	rm -rf "${DIR}"
    else
	dprint "In DEBUG mode, not cleaning up log files in $DIR"
    fi
}

signal()
{
    echo
    if [ "$1" != "EXIT" ]; then
	print "Got signal $1, cleaning up ..."
    fi
    teardown
}

# props to https://stackoverflow.com/a/2183063/1708249
# shellcheck disable=SC2064
trapit()
{
    func=$1; shift
    for sig; do
        trap "$func $sig" "$sig"
    done
}

# Runs once when including lib.sh
mkdir -p "${CONFD}"
mkdir -p "${CONFD2}"
touch "$DIR/PIDs"
trapit signal INT TERM QUIT EXIT

# When running tests standalone, not for `make check`
if [ -z "$srcdir" ]; then
    export srcdir="."
    print "Reexec $0 in an unshare ..."
    exec unshare -mrun "$0"
fi
