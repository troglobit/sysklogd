#!/bin/sh
# Start, SIGHUP, and log a run of syslogd under Valgrind
. "${srcdir:-.}/lib.sh"

setup_valgrind()
{
    VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
    DEBUG=true

    # Only needed for verifying correct RFC3164 parsing
    cat <<-EOF >"${CONFD}/99-wall.conf"
	*.=emerg	*
	EOF
    setup -m0 >"${LOG2}" 2>&1
}

inject_logger()
{
    logger "Dummy message"
    sleep 1			# Wait for any OS delays
}

inject_reload()
{
    reload
    sleep 1			# Wait for any OS delays
}

verify_leaks()
{
    kill_pids
    sleep 2			# Wait for syslogd to shut down
    grep "All heap blocks were freed -- no leaks are possible" "$LOG2"
}

run_step "Start basic syslogd under valgrind"  setup_valgrind
run_step "Inject stimuli: logger"              inject_logger
run_step "Inject stimuli: reload"              inject_reload
run_step "Verify no leaks in valgrind output"  verify_leaks
