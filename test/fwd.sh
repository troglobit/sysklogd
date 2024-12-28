#!/bin/sh
# Verify FWD between two syslogd, second binds 127.0.0.2:5555
#
# Three types of messages are sent:
#  1. A "normal" message, way shorter than any limit
#  2. A long message, matching the udp_size value
#  3. A too long message, truncated to the udp_size value
#
# shellcheck disable=SC1090
if [ -z "${srcdir}" ]; then
    srcdir=.
fi
. "${srcdir}/lib.sh"

# Constants
MAX_UDP_PAYLOAD=480
HEADER="<101>1 2024-12-27T10:39:30.440026+01:00 $(hostname) fwd - NTP123 - "
HEADER_LEN=${#HEADER}
AVAILABLE_MSG_LEN=$((MAX_UDP_PAYLOAD - HEADER_LEN))

[ ${AVAILABLE_MSG_LEN} -le 0 ] && FAIL "Header is too long for the udp_size limit."

# Generate Messages
MSG="short message"
LONG_MSG=$(printf "%-${AVAILABLE_MSG_LEN}s" | tr ' ' 'A')
TOO_LONG_MSG=$(printf "%-$((AVAILABLE_MSG_LEN + 100))s" | tr ' ' 'B')

setup_sender()
{
    # Cap UDP payload to 480 octets
    cat <<-EOF >"${CONFD}/fwd.conf"
	udp_size        ${MAX_UDP_PAYLOAD}
	kern.*		/dev/null
	ntp.*		@[::1]:${PORT2}	;RFC5424
	EOF
    setup -m0
}

setup_receiver()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	kern.*		/dev/null
	*.*;kern.none	${LOG2}			;RFC5424
	EOF
    setup2 -m0 -a "[::1]:*" -b ":${PORT2}"
}

# Helper function to send and verify reception
send_and_verify()
{
    msg="$1"
    expected="$2"

    logger -t fwd -p ntp.notice -m "NTP123" "${msg}"
    sleep 3  # Allow message to be received, processed, and forwarded

    logged_msg=$(grep "fwd - NTP123 -" "${LOG2}" |tail -1)
    message=$(echo "$logged_msg" | sed -n "s/.*fwd - NTP123 - //p")
    if [ "${message}" != "${expected}" ]; then
        echo "EXPECTED: ${expected}"
        echo "GOT:      ${message}"
        FAIL
    fi
    dprint "OK, got: $logged_msg"
}

verify_msg()
{
    send_and_verify "${MSG}" "${MSG}"
}

verify_forward()
{
    send_and_verify "${LONG_MSG}" "${LONG_MSG}"
}

verify_capped()
{
    send_and_verify "${TOO_LONG_MSG}" \
		    "$(echo "${TOO_LONG_MSG}" | cut -c1-${AVAILABLE_MSG_LEN})"
}

run_step "Set up sender syslogd to log in RFC5424 format"            setup_sender
run_step "Set up receiver syslogd to log to file in RFC5424 format"  setup_receiver
run_step "Verify forward of normal message"                          verify_msg
run_step "Verify forward of long message (480 chars)"                verify_forward
run_step "Verify truncation of too-long message"                     verify_capped
