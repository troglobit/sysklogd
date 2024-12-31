#!/bin/sh
# Verify actual (minor) regressions that we've had in the project
. "${srcdir:-.}/lib.sh"

verify_tagpid()
{
    logger -t foo -I 1234 "You won't get it up the steps."
    grep -H 'foo\[1234\]' "$LOG"
}

run_step "Set up local syslog daemon" setup -m0
run_step "Verify tag[PID] regression" verify_tagpid
