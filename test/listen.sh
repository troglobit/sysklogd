#!/bin/sh
# Verify listen changes in .conf file at runtime w/o having to restart
# syslogd.  We want to ensure adding and removing listen addresses work
# as intended.
. "${srcdir:-.}/lib.sh"

#
# Helper functions
#

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
	setup0 10.0.0.1/24 -m0
    fi
}

do_port_check()
{
    dprint "Checking for port $1"
    netstat -atnu | grep "$1"
}

check_not_open()
{
    do_port_check "$1" || return 0
}

check_port_open()
{
    do_port_check "$1"
}

#
# Test steps
#

verify_secure_daemon()
{
    set_listen 2
    check_not_open 514
}

verify_safe_daemon()
{
    set_listen 1
    check_not_open 514
}

verify_default_daemon()
{
    set_listen 0
    check_port_open 514
}

verify_local_daemon()
{
    set_listen 0 127.0.0.1:510
    check_port_open 510
}

verify_bind()
{
    set_listen 0 10.0.0.1:512
    check_port_open 512
}

verify_delayed_bind()
{
    addr=10.0.0.2
    port=513

    set_listen 0 $addr:$port
    sleep 1

    dprint "Delayed add of bind address $addr:$port ..."
    ip addr add "$addr"/24 dev eth0

    dprint "Waiting for syslogd to react ..."
    sleep 5

    check_port_open $port
}

#
# Run test steps
#

run_step "Verify listen off - no remote no ports"             verify_secure_daemon
run_step "Verify listen off - only send to remote, no ports"  verify_safe_daemon
run_step "Verify listen on, default"                          verify_default_daemon

run_step "Verify listen on 127.0.0.1:510"                     verify_local_daemon
run_step "Verify port 514 is closed"                          check_not_open 514

run_step "Verify listen on 10.0.0.1:512"                      verify_bind
run_step "Verify port 510 is closed"                          check_not_open 510

run_step "Verify delayed bind to new address 10.0.0.2:513"    verify_delayed_bind
run_step "Verify port 512 is closed"                          check_not_open 512
