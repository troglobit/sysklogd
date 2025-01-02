#!/bin/sh
# Verify that the sending to a remote IP:PORT works.
# shellcheck disable=SC2317
. "${srcdir:-.}/lib.sh"

setup_remote()
{
    cat <<-EOF > "${CONF}"
	*.* @127.0.0.2:${PORT2}	;RFC3164
	EOF
    setup -m0
}

verify_remote()
{
    MSG="kilroy"

    cap_start "$PORT2"
    logger    "${MSG}"
    cap_stop

    cap_find_port "$PORT2" "${MSG}"
}

run_step "Setup remote syslog, RFC3164" setup_remote
run_step "Verify sending to remote"     verify_remote
