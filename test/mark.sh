#!/bin/sh -e
# Test '-- MARK --' in log, depends on fwd.sh
. ./start.sh

check_mark()
{
    grep "MARK" "${LOG}" && return 0
    sleep 1
    return 1
}

tenacious 120 check_mark

. ./stop.sh
