#!/bin/sh
# Verify listen changes in .conf file at runtime w/o having to restart
# syslogd.  We want to ensure adding and removing listen addresses work
# as intended.
#
# shellcheck disable=SC1090
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

set_listen()
{
    echo "secure_mode $1" > "${CONF}"
    shift 1
    for l in "$@"; do
	echo "listen $l" >> "${CONF}"
    done

    if is_running; then
	reload
    else
	dprint "Not running, calling setup0 -m0"
	setup0 -m0
    fi
}

do_port_check()
{
    dprint "Checking for port $1"
    netstat -atnu | grep "$1"
}

check_not_open()
{
    PORT=$1
    shift 1
    do_port_check "$PORT" && FAIL "$@"
}

check_port_open()
{
    PORT=$1
    shift 1
    do_port_check "$PORT" || FAIL "$@"
}

print "Listen off - no remote no ports"
set_listen 2
check_not_open 514 "Listen off, yet ports are opened!"

print "Listen off - only send to remote, no ports"
set_listen 1
check_not_open 514 "Listen still off, yet ports are opened!"

print "Listen on, default"
set_listen 0
check_port_open 514 "Expected port 514 to be open!"

print "Listen on 127.0.0.1:510"
set_listen 0 127.0.0.1:510
check_not_open  514 "Port 514 still open!"
check_port_open 510 "Expected port 510 to be open!"

print "Listen on 10.0.0.1:512"
set_listen 0 10.0.0.1:512
check_not_open  510 "Port 510 still open!"
check_port_open 512 "Expected port 512 to be open!"

print "Listen on 10.0.0.2:513"
set_listen 0 10.0.0.2:513
sleep 1
dprint "Delayed add of bind address ..."
ip addr add 10.0.0.2/24 dev eth0
ip -br a
dprint "Waiting for syslogd to react ..."
sleep 5
netstat -atnu
check_not_open  512 "Port 512 still open!"
check_port_open 513 "Expected port 513 to be open!"

OK
