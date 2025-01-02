#!/bin/sh
. "${srcdir:-.}/lib.sh"

MSG="Copying foobar to xyzzy"
GROUP=225.1.2.3
TTL=10

setup_sender()
{
    cat <<-EOF >"${CONF}"
	*.*		@$GROUP	;RFC5424,ttl=$TTL
	EOF
    setup -m0

    ip route add default via 127.0.0.1
}

setup_receiver()
{
    cat <<-EOF > "${CONF2}"
	uucp.info	$LOG2
	listen		$GROUP
	EOF
    setup2 -m0 -nH
}

verify_mcast_fwd()
{
    cap_start
    logger -p uucp.info "$MSG"
    cap_stop

    cap_find "$MSG"
}

verify_mcast_ttl()
{
    ttl=$(cap_find "$MSG" |awk '{print $2}')
    test "$ttl" -eq "$TTL"
}

verify_mcast_rcv()
{
    grep -H "$MSG" "$LOG2"
}

run_step "Set up sender syslogd"      setup_sender
run_step "Set up receiver syslogd"    setup_receiver
run_step "Verify multicast forward"   verify_mcast_fwd
run_step "Verify multicast TTL=$TTL"  verify_mcast_ttl
run_step "Verify multicast received"  verify_mcast_rcv
