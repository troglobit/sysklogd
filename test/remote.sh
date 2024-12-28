#!/bin/sh
# Verify that the sending to a remote IP:PORT works.
#
# shellcheck disable=SC1090,SC2317
if [ -z "${srcdir}" ]; then
    srcdir=.
fi
. "${srcdir}/lib.sh"

setup_remote()
{
    cat <<-EOF > "${CONF}"
	*.* @127.0.0.2
	*.* @127.0.0.2:${PORT2}	;RFC3164
	EOF
    setup -m0
}

verify_remote()
{
    MSG="kilroy"

    cap_start
    logger   "${MSG}"
    cap_stop

    cap_find "${MSG}"
}

run_step "Setup remote syslog, RFC3164" setup_remote
run_step "Verify sending to remote"     verify_remote
