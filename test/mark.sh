#!/bin/sh
# Test '-- MARK --' in log, runs in full secure mode.
. "${srcdir:-.}/lib.sh"

run_step "Enable -- MARK -- every minute" setup -m1 -ss
run_step "Verify -- MARK -- in log file"  tenacious 120 grep "MARK" "${LOG}"
