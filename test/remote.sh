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

    # Start collector in background, note: might need sudo!
    tshark -Qni lo -w "${CAP}" port 514 2>/dev/null &
    TPID="$!"
    echo "$TPID" >> "$DIR/PIDs"

    # While waiting for tshark to start we take the opportunity
    # to verify syslogd can survive a few SIGHUP's.
    for _ in $(seq 3); do
	reload
    done

    # Now send the message and see if we sent it ...
    logger "${MSG}"

    # Wait for any OS delays, in particular CI
    sleep 1

    # Stop tshark collector
    kill -TERM "${TPID}"
    wait "${TPID}"

    # Analyze content, should have $MSG now ...
    tshark -r "${CAP}" 2>/dev/null | grep "${MSG}"
}

run_step "Setup remote syslog, RFC3164" setup_remote
run_step "Verify sending to remote"     verify_remote
