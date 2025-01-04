#!/bin/sh
# Verify:
#  - calling logger with a multicast group on an interface that would
#    not be selected from the routing table
#  - a syslogd listening to the same group on the same LAN
#
# Noite: unlike other tests, this test relies on a more elaborate
#        network setup using a veth pair.
#
. "${srcdir:-.}/lib.sh"

MSG1="Supersonic, ASOT 253"
MSG2="Beautiful, ASOT 253"
GROUP=225.3.2.1
TTL=3


# Runs in a nested unshare and responsible for setting up veth pair
setup_receiver()
{
    SYSLOGD=$(realpath ../src/syslogd)
    SYSLOGD_ARGS="-KF -m0 -nH"

    cat <<-EOF > "${CONF2}"
	uucp.info	$LOG2
	listen		$GROUP%veth0b
	EOF
    cat <<-EOF > "$DIR/setup.sh"
	sleep 1			# wait for parent to create veth pair

	ip link set lo up
	ip route add default via 127.0.0.1

	ip addr add 192.168.0.2/24 dev veth0b
	ip link set veth0b multicast on up state up

	exec $SYSLOGD $SYSLOGD_ARGS -f "${CONF2}" -p "${SOCK2}" -P "${PID2}"
	EOF
    chmod +x "$DIR/setup.sh"

    unshare -mrun "$DIR/setup.sh" &
    pid=$(echo $! | tee -a "$DIR/PIDs")
    dprint "Started as PID $pid"

    ip link add veth0a type veth peer veth0b
    ip link set veth0b netns "$pid"
    ip addr add 192.168.0.1/24 dev veth0a
    ip link set veth0a multicast on up state up
}

# Runs in first unshare
setup_sender()
{
    cat <<-EOF >"${CONF}"
	*.*		@$GROUP	;RFC5424,iface=veth0a,ttl=$TTL
	EOF
    setup0 172.16.31.12 -m0 -s
}

verify_mcast_fwd()
{
    cap_start veth0a 514
    logger -p uucp.info "$MSG2"
    cap_stop

    cap_find "$MSG2"
}

verify_mcast_ttl()
{
    ttl=$(cap_find "$MSG2" |awk '{print $2}')
    test "$ttl" -eq "$TTL"
}

verify_mcast_rcv()
{
    grep -H "$MSG2" "$LOG2"
}

verify_logger_send()
{
    cap_start veth0a 514
    logger -H logger -p uucp.info -h "$GROUP" -o iface=veth0a "$MSG1"
    cap_stop

    cap_find "$MSG1"
}

verify_logger_recv()
{
    grep -H "$MSG1" "$LOG2"
}

run_step "Set up receiver syslogd"          setup_receiver
run_step "Set up sender syslogd"            setup_sender

run_step "Verify multicast forward"         verify_mcast_fwd
run_step "Verify multicast TTL=$TTL"        verify_mcast_ttl
run_step "Verify multicast received"        verify_mcast_rcv

run_step "Verify logger to group + iface"   verify_logger_send
run_step "Verify logger message received"   verify_logger_recv
