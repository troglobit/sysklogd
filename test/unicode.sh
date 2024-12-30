#!/bin/sh
# Currently only same as local.sh but with unicode messages
# From https://github.com/troglobit/sysklogd/issues/49
. "${srcdir:-.}/lib.sh"

run_step "Set up unicode capable syslogd" setup -8 -m0
run_step "Verify logger"                  log_and_find "öäüÖÄÜß€¢§"
run_step "Verify logger w/ alt. socket"   log_and_find "$ALTSOCK" "…‘’•"
