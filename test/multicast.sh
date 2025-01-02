#!/bin/sh
. "${srcdir:-.}/lib.sh"

GROUP=225.1.2.3

setup_listen()
{
    ip link set lo up state up
    ip route add default via 127.0.0.1

    cat <<-EOF > "${CONF}"
	*.*	$LOG
	listen  $1:$PORT2
	EOF
    setup -m0
}

verify_listen()
{
    MSG="kilroy was here"

    logger -h "$GROUP" -P "$PORT2" "${MSG}"
    grep -H "${MSG}" "$LOG"
}

run_step "Set up syslogd that listen to $GROUP"  setup_listen  "$GROUP"
run_step "Verify sending to group $GROUP"        verify_listen "$GROUP"
