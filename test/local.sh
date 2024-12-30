#!/bin/sh
. "${srcdir:-.}/lib.sh"

run_step "Set up local syslog daemon" setup -m0
run_step "Verify basic logging"       log_and_find "foobar"
run_step "Verify alternate socket"    log_and_find "$ALTSOCK" "xyzzy"
