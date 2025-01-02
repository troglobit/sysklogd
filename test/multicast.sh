#!/bin/sh
. "${srcdir:-.}/lib.sh"

GROUP=225.1.2.3
MSG="kilroy was here"

setup_listen()
{
    ip link set lo up state up
    ip route add default via 127.0.0.1

    cat <<-EOF > "${CONF}"
	*.*	$LOG
	listen  $1:$PORT2
	EOF
    setup -m0 -nH
}

verify_snd()
{
    cap_start "$PORT2"
    logger -h "$GROUP" -H remote -P "$PORT2" "${MSG}"
    cap_stop
    cap_find_port "$PORT2" "${MSG}"
}

verify_rcv()
{
    grep -H "${MSG}" "$LOG"
}

run_step "Set up syslogd that listen to $GROUP"  setup_listen  "$GROUP"
run_step "Verify sending to group $GROUP"        verify_snd    "$GROUP"
run_step "Verify reception from group $GROUP"    verify_rcv    "$GROUP"
