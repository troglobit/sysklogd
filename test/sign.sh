#!/bin/sh
# Verify RFC 5848 signed syslog support.
#
# Confirms that the certificate block and signature blocks are actually
# emitted to the configured destination, and that a signature block
# verifies cryptographically against the signing certificate -- a
# tampered payload must NOT verify.
#
. "${srcdir:-.}/lib.sh"

SLOG="${DIR}/signed.log"

check_openssl()
{
    command -v openssl >/dev/null || SKIP "OpenSSL CLI not available"
}

setup_keys()
{
    openssl genrsa -out "${DIR}/test.key" 2048 2>/dev/null
    openssl req -new -x509 -key "${DIR}/test.key" -out "${DIR}/test.cert" \
	-days 1 -subj "/CN=syslog-test" 2>/dev/null
    openssl x509 -in "${DIR}/test.cert" -pubkey -noout > "${DIR}/test.pub"
    chmod 600 "${DIR}/test.key"
}

setup_signer()
{
    cat <<-EOF >"${CONFD}/sign.conf"
	sign_sg        0
	sign_keyfile   ${DIR}/test.key
	sign_certfile  ${DIR}/test.cert
	*.*            ${SLOG}    ;RFC5424
	EOF
    setup -m0
}

# Send messages, then stop syslogd so sign_exit() flushes the final
# signature block -- avoids waiting for the 30s block timer.
flush_blocks()
{
    for i in 1 2 3 4 5; do
	logger -t signtest "signed payload $i"
    done
    sleep 1
    kill "$(cat "${PID}")"
    tenacious 5 grep -q '\[ssign VER=' "${SLOG}"
}

# The certificate block is emitted at startup.
verify_cert_block()
{
    grep -q '\[ssign-cert VER=' "${SLOG}"
}

# Reconstruct the signed payload exactly as src/sign.c assembles it
# ("VER RSID SG SPRI GBC FMN CNT HB", no trailing newline) and verify
# the SIGN value against the certificate's public key.
verify_signature_crypto()
{
    line=$(grep -o '\[ssign VER[^]]*]' "${SLOG}" | head -1)
    [ -n "$line" ] || return 1
    get() { echo "$line" | sed -n "s/.*$1=\"\([^\"]*\)\".*/\1/p"; }

    printf '%s %s %s %s %s %s %s %s' \
	"$(get VER)" "$(get RSID)" "$(get SG)" "$(get SPRI)" \
	"$(get GBC)" "$(get FMN)" "$(get CNT)" "$(get HB)" > "${DIR}/signed.bin"
    printf '%s' "$(get SIGN)" | openssl base64 -d -A > "${DIR}/sig.bin"

    openssl dgst -sha256 -verify "${DIR}/test.pub" \
	-signature "${DIR}/sig.bin" "${DIR}/signed.bin" >/dev/null 2>&1
}

# A tampered payload must fail verification -- proves the test checks the
# signature itself, not merely the presence of an [ssign] string.
verify_tamper_rejected()
{
    printf 'X%s' "$(cat "${DIR}/signed.bin")" > "${DIR}/bad.bin"
    openssl dgst -sha256 -verify "${DIR}/test.pub" \
	-signature "${DIR}/sig.bin" "${DIR}/bad.bin" >/dev/null 2>&1 && return 1
    return 0
}

run_step "Check OpenSSL availability"            check_openssl
run_step "Generate test keys"                    setup_keys
run_step "Set up syslogd with signing enabled"   setup_signer
run_step "Flush a signature block"               flush_blocks
run_step "Verify certificate block emitted"      verify_cert_block
run_step "Verify signature cryptographically"    verify_signature_crypto
run_step "Verify tampered payload is rejected"   verify_tamper_rejected
