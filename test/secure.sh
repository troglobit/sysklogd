#!/bin/sh
# Verify secure_mode changes at runtime w/o having to restart syslogd.
# We want to ensure goint from most secure, to no security, and back,
# works as intended.
. "${srcdir:-.}/lib.sh"

MSG="Kilroy was here"

#
# Helper functions
#

set_secure_mode()
{
    cat <<-EOF > "${CONF}"
	*.* @127.0.0.2
	secure_mode=$1
	EOF

    if is_running; then
	reload
    else
	setup -m0
    fi

    sleep 1			# Wait for any OS delays
}

do_port_check()
{
    dprint "Checking for port $PORT|$PORT2 ..."
    netstat -atnup | grep "$PORT\|$PORT2"
}

check_no_port_open()
{
    do_port_check || return 0
}

check_port_open()
{
    do_port_check
}

check_remote_logging()
{
    cap_start
    logger   "$MSG"
    cap_stop

    cap_find "$MSG"
}

#
# Test steps
#

verify_secure_daemon()
{
    set_secure_mode 2
    check_no_port_open
}

verify_safe_daemon()
{
    set_secure_mode 1
    check_no_port_open
}

verify_default_daemon()
{
    set_secure_mode 0
    check_port_open
}

#
# Run test steps
#

run_step "Verify secure mode 2 - no remote no ports" verify_secure_daemon

run_step "Verify secure mode 1 - remote, no ports"   verify_safe_daemon
run_step "Verify                 remote logging"     check_remote_logging

run_step "Verify secure mode 0 - remote, open ports" verify_default_daemon
run_step "Verify                 remote logging"     check_remote_logging

run_step "Verify secure mode 1 - remote, no ports"   verify_safe_daemon
run_step "Verify                 remote logging"     check_remote_logging
