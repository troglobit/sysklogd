#!/bin/sh
# Verify TLS client authentication (mutual TLS) for RFC 5425 forwarding.
#
# A strict receiver (tls_verify required + tls_cafile) demands a client
# certificate; the forwarding sender presents one via the per-action
# tls_keyfile=/tls_certfile= options.  Also verifies that a sender
# without a client certificate is rejected.
#
. "${srcdir:-.}/lib.sh"

MSG_MTLS="mtls authenticated message"
MSG_NOAUTH="mtls clientless message"

check_openssl()
{
    command -v openssl >/dev/null || SKIP "OpenSSL CLI not available"
}

# A CA, a server certificate signed by it (CN=localhost), and a client
# certificate signed by it.
setup_ca()
{
    openssl genrsa -out "${DIR}/ca.key" 2048 2>/dev/null
    openssl req -new -x509 -key "${DIR}/ca.key" -out "${DIR}/ca.cert" \
	-days 1 -subj "/CN=Test CA" 2>/dev/null

    openssl genrsa -out "${DIR}/server.key" 2048 2>/dev/null
    openssl req -new -key "${DIR}/server.key" -out "${DIR}/server.csr" \
	-subj "/CN=ip6-localhost" 2>/dev/null
    openssl x509 -req -in "${DIR}/server.csr" -CA "${DIR}/ca.cert" \
	-CAkey "${DIR}/ca.key" -CAcreateserial -out "${DIR}/server.cert" \
	-days 1 2>/dev/null

    openssl genrsa -out "${DIR}/client.key" 2048 2>/dev/null
    openssl req -new -key "${DIR}/client.key" -out "${DIR}/client.csr" \
	-subj "/CN=fwd-client" 2>/dev/null
    openssl x509 -req -in "${DIR}/client.csr" -CA "${DIR}/ca.cert" \
	-CAkey "${DIR}/ca.key" -CAcreateserial -out "${DIR}/client.cert" \
	-days 1 2>/dev/null

    # An untrusted (self-signed, not CA-signed) server cert, and a
    # CA-signed server cert with the wrong CN, for verify-mode tests.
    openssl req -new -x509 -nodes -keyout "${DIR}/server-bad.key" \
	-out "${DIR}/server-bad.cert" -days 1 -subj "/CN=localhost" 2>/dev/null
    openssl genrsa -out "${DIR}/server-wrong.key" 2048 2>/dev/null
    openssl req -new -key "${DIR}/server-wrong.key" \
	-out "${DIR}/server-wrong.csr" -subj "/CN=wrong.example" 2>/dev/null
    openssl x509 -req -in "${DIR}/server-wrong.csr" -CA "${DIR}/ca.cert" \
	-CAkey "${DIR}/ca.key" -out "${DIR}/server-wrong.cert" -days 1 2>/dev/null

    chmod 600 "${DIR}/ca.key" "${DIR}/server.key" "${DIR}/client.key" \
	"${DIR}/server-bad.key" "${DIR}/server-wrong.key"
}

# Receiver requires and validates a client certificate against the CA.
setup_receiver_mtls()
{
    cat <<-EOF >"${CONFD2}/50-default.conf"
	tls_keyfile   ${DIR}/server.key
	tls_certfile  ${DIR}/server.cert
	tls_cafile    ${DIR}/ca.cert
	tls_verify    required
	kern.*        /dev/null
	*.*;kern.none ${LOG2}       ;RFC5424
	listen        tls://[::1]:${PORT2}
	EOF
    setup2 -m0 -a "[::1]:*"
}

# Sender presents its client certificate.  verify=off so the test
# isolates client authentication from server-cert verification.
setup_sender_mtls()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*  /dev/null
	ntp.*   @@@[::1]:${PORT2}  ;RFC5424,verify=off,tls_keyfile=${DIR}/client.key,tls_certfile=${DIR}/client.cert
	EOF
    setup -m0
}

verify_mtls()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG_MTLS}"
    tenacious 5 grep "${MSG_MTLS}" "${LOG2}"
}

# Reconfigure the sender without a client certificate; the strict
# receiver must reject the handshake so the message never arrives.
setup_sender_noauth()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	kern.*  /dev/null
	ntp.*   @@@[::1]:${PORT2}  ;RFC5424,verify=off
	EOF
    reload
    sleep 1
}

verify_noauth_blocked()
{
    logger -t fwd -p ntp.notice -m "NTP123" "${MSG_NOAUTH}"
    sleep 2
    grep "${MSG_NOAUTH}" "${LOG2}" && return 1
    return 0
}

MSG_REQ_OK="verify required accept message"
MSG_HOST_OK="verify hostname accept message"
MSG_REQ_BAD="verify required reject message"
MSG_OPT="verify optional accept message"
MSG_HOST_BAD="verify hostname reject message"

# Restart the receiver presenting server cert "$1" (basename under $DIR),
# without requiring a client cert -- for server-cert verification tests.
# The server SSL context is built once at startup, so a fresh process is
# needed to change the presented certificate.
restart_receiver_srv()
{
    [ -f "${PID2}" ] && kill "$(cat "${PID2}")" 2>/dev/null
    rm -f "${PID2}"
    sleep 1
    cat <<-EOF >"${CONFD2}/50-default.conf"
	tls_keyfile   ${DIR}/$1.key
	tls_certfile  ${DIR}/$1.cert
	kern.*        /dev/null
	*.*;kern.none ${LOG2}       ;RFC5424
	listen        tls://[::1]:${PORT2}
	EOF
    setup2 -m0 -a "[::1]:*"
}

# Sender config: trust the CA globally, forward with verify mode "$1"
# to target "$2".
write_sender_conf()
{
    cat <<-EOF >"${CONFD}/fwd.conf"
	tls_cafile        ${DIR}/ca.cert
	tcp_suspend_time  3
	kern.*            /dev/null
	ntp.*             tls://$2:${PORT2}  ;RFC5424,verify=$1
	EOF
}

# (Re)start the sender.  Restarted (not reloaded) because the client CA
# store is baked into the SSL context at startup; the per-action verify
# mode can then be changed with sender_verify() via reload.
restart_sender()
{
    [ -f "${PID}" ] && kill "$(cat "${PID}")" 2>/dev/null
    rm -f "${PID}"
    sleep 1
    write_sender_conf "$1" "$2"
    setup -m0
}

sender_verify()
{
    write_sender_conf "$1" "$2"
    reload
    sleep 1
}

fwd_arrives()
{
    logger -t fwd -p ntp.notice -m "NTP123" "$1"
    tenacious 5 grep "$1" "${LOG2}"
}

fwd_blocked()
{
    logger -t fwd -p ntp.notice -m "NTP123" "$1"
    sleep 2
    grep "$1" "${LOG2}" && return 1
    return 0
}

verify_required_accept()  { fwd_arrives "${MSG_REQ_OK}"; }
verify_hostname_accept()  { fwd_arrives "${MSG_HOST_OK}"; }
verify_required_reject()  { fwd_blocked "${MSG_REQ_BAD}"; }
verify_optional_accept()  { fwd_arrives "${MSG_OPT}"; }
verify_hostname_reject()  { fwd_blocked "${MSG_HOST_BAD}"; }

run_step "Check OpenSSL availability"               check_openssl
run_step "Generate CA, server and client certs"     setup_ca
run_step "Set up receiver requiring a client cert"  setup_receiver_mtls
run_step "Set up sender with a client certificate"  setup_sender_mtls
run_step "Verify mutual-TLS authenticated forward"  verify_mtls
run_step "Reconfigure sender without client cert"   setup_sender_noauth
run_step "Verify clientless forward is rejected"    verify_noauth_blocked

# Server-certificate verification modes (client side)
run_step "Receiver presents CA-signed cert"         restart_receiver_srv server
run_step "Sender trusts CA, verify=required"         restart_sender required "[::1]"
run_step "verify=required accepts trusted cert"     verify_required_accept
run_step "Sender verify=hostname to ip6-localhost"      sender_verify hostname ip6-localhost
run_step "verify=hostname accepts matching CN"      verify_hostname_accept
run_step "Receiver presents untrusted self-signed"  restart_receiver_srv server-bad
run_step "Sender verify=required (untrusted)"        sender_verify required "[::1]"
run_step "verify=required rejects untrusted cert"   verify_required_reject
run_step "Sender verify=optional (untrusted)"        sender_verify optional "[::1]"
run_step "verify=optional accepts untrusted cert"   verify_optional_accept
run_step "Receiver presents CA-signed wrong CN"     restart_receiver_srv server-wrong
run_step "Sender verify=hostname to ip6-localhost"      sender_verify hostname ip6-localhost
run_step "verify=hostname rejects wrong CN"         verify_hostname_reject
