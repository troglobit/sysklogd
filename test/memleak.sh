#!/bin/sh
# Start, SIGHUP, and log a run of syslogd under Valgrind
# shellcheck disable=SC1090
#set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi

# shellcheck disable=SC2034
VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
. ${srcdir}/lib.sh

# Only needed for verifying correct RFC3164 parsing
cat <<-EOF >"${CONFD}/99-wall.conf"
	*.=emerg	*
	EOF
setup


print "TEST: Starting"

#../src/logger -u "${SOCK}" ${MSG}

# Wait for any OS delays
#sleep 1

reload
sleep 1

OK
