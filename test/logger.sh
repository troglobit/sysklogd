#!/bin/sh
# Verify logger capabilities, for now just remote logger
. "${srcdir:-.}/lib.sh"

setup_loopback()
{
    ip link set lo up
}

verify_logger()
{
    cap_start
    logger -b -H "$(basename "$0")" -h 127.0.0.3 -I $$ -t test1 "Kilroy was here"
    cap_stop

    # Check for the composed BSD procname{PID] syntax
    STR="test1\[$$\]"
    cap_find "$STR"
}

run_step "Set up loopback interface"                    setup_loopback
run_step "Verify remote syslog with stand-alone logger" verify_logger
