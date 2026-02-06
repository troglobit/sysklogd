#!/bin/sh
# Verify TLS forwarding between two syslogd instances (RFC 5425)
#
# Tests both @@@ and tls:// syntax for TLS forwarding.
# Requires OpenSSL CLI for certificate generation.
#
. "${srcdir:-.}/lib.sh"

MSG="tls fwd test message"
MSG2="tls fwd url test message"

check_openssl()
{
    command -v openssl >/dev/null || SKIP "OpenSSL CLI not available"
}

setup_certs()
{
    # Generate self-signed certificate for testing
    openssl genrsa -out "${DIR}/server.key" 2048 2>/dev/null
    openssl req -new -x509 -key "${DIR}/server.key" \
        -out "${DIR}/server.cert" -days 1 -subj "/CN=localhost" 2>/dev/null
    chmod 600 "${DIR}/server.key"
}

setup_receiver_tls()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	tls_keyfile   ${DIR}/server.key
	tls_certfile  ${DIR}/server.cert
	kern.*        /dev/null
	*.*;kern.none ${LOG2}       ;RFC5424
	listen        tls://[::1]:${PORT2}
	EOF
    setup2 -m0 -a "[::1]:*"
}

setup_sender_tls()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*        /dev/null
	ntp.*         @@@[::1]:${PORT2}    ;RFC5424,verify=off
	EOF
    setup -m0
}

setup_sender_tls_url()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*        /dev/null
	ntp.*         tls://[::1]:${PORT2} ;RFC5424,verify=off
	EOF
    reload
    sleep 1
}

verify_msg()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG}"
    sleep 3

    grep "fwd - NTP123 - ${MSG}" "${LOG2}"
}

verify_msg_url()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG2}"
    sleep 3

    grep "fwd - NTP123 - ${MSG2}" "${LOG2}"
}

run_step "Check OpenSSL availability"                          check_openssl
run_step "Generate test certificates"                          setup_certs
run_step "Set up receiver syslogd with TLS listener"           setup_receiver_tls
run_step "Set up sender syslogd with @@@ TLS forwarding"       setup_sender_tls
run_step "Verify TLS forward of message using @@@ syntax"      verify_msg
run_step "Reconfigure sender to use tls:// URL syntax"         setup_sender_tls_url
run_step "Verify TLS forward of message using tls:// syntax"   verify_msg_url
