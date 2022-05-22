#!/bin/sh
# Verify secure_mode changes at runtime w/o having to restart syslogd.
# We want to ensure goint from most secure, to no security, and back,
# works as intended.
#
# shellcheck disable=SC1090
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

MSG="Kilroy was here"

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
	sleep 1
}

do_port_check()
{
	netstat -atnup | grep "$PORT\|PORT2"
}

check_no_port_open()
{
	do_port_check && FAIL "$@"
}

check_port_open()
{
	do_port_check || FAIL "$@"
}

check_remote_logging()
{
	cap_start
	logger "$MSG"
	cap_stop
	cap_find "$MSG" || FAIL "Cannot find: $MSG"
}

print "Secure mode 2 - no remote no ports"
set_secure_mode 2
check_no_port_open "Secure mode 2, yet ports are opened!"

print "Secure mode 1 - remote but no ports"
set_secure_mode 1
check_no_port_open "Secure mode 1, yet ports are opened!"
check_remote_logging

print "Secure mode 0 - remote and open ports"
set_secure_mode 0
check_remote_logging "Secure mode 0, but no ports open!"
check_port_open

print "Secure mode 1 - remote but no ports"
set_secure_mode 1
check_no_port_open "Secure mode 1, yet ports are opened!"
check_remote_logging

OK
