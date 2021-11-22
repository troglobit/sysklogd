#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/test.rc

# Print heading for test phases
print()
{
    printf "\e[7m>> %-76s\e[0m\n" "$1"
}

dprint()
{
    printf "\e[2m%-76s\e[0m\n" "$1"
}

SKIP()
{
    print "TEST: SKIP"
    [ $# -gt 0 ] && echo "$*"
    exit 77
}

FAIL()
{
    print "TEST: FAIL"
    [ $# -gt 0 ] && echo "$*"
    exit 99
}

OK()
{
    print "TEST: OK"
    [ $# -gt 0 ] && echo "$*"
    exit 0
}

# shellcheck disable=SC2068
tenacious()
{
    timeout=$1
    shift

    while [ $timeout -gt 0 ]; do
	$@ && return
	timeout=$((timeout - 1))
    done

    FAIL "Timeed out $*"
}

ip link set lo up

mkdir -p ${CONFD}
cat <<EOF > ${CONF}
# Nothing here yo
include ${CONFD}/*.conf
EOF

mkdir -p ${CONFD2}
cat <<EOF > ${CONF2}
# Nothing here yo
include ${CONFD2}/*.conf
EOF

cat <<EOF > ${CONFD}/foo.conf
# Local log file, avoid sync to disk
*.*	-${LOG}
EOF

cat <<EOF > ${CONFD}/bar.conf
# For remote logging
*.*	@127.0.0.2
EOF

../src/syslogd -m1 -b :${PORT} -d -sF -f ${CONF} -p ${SOCK} -p ${ALTSOCK} -C ${CACHE} -P ${PID} &

sleep 2
kill -USR1 `cat ${PID}`
sleep 1
