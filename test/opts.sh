#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

mkdir -p ${CONFD}
cat <<EOF > ${CONF}
# Match all log messages, store in RC5424 format and rotate every 10 MiB
*.*       -${LOG}    ;rotate=10M:5,RFC5424
EOF

../src/syslogd -K -m1 -b :${PORT} -d -sF -f ${CONF} -p ${SOCK} -p ${ALTSOCK} >${LOG2} &
echo "$!" > ${PID}
cat ${PID} >> "$DIR/PIDs"

sleep 2
grep ';RFC5424,rotate=10000000:5' ${LOG2} || FAIL "Failed parsing RFC542 .conf"
