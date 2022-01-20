#!/bin/sh
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

NOT1=${DIR}/${NM}-1.sh
echo $NOT1 > /tmp/Xxxxx
NOT1STAMP=${DIR}/${NM}-1.stamp
NOT2=${DIR}/${NM}-2.sh
NOT2STAMP=${DIR}/${NM}-2.stamp

printf '#!/bin/sh -\necho script 1: $* > '${NOT1STAMP}'\n' > ${NOT1}
chmod 0755 ${NOT1}

cat <<EOF > ${CONF}
notify ${NOT1}
*.*       -${LOG}    ;rotate=10k:2,RFC5424
*.*       -${LOG}X   ;rotate=10k:2,RFC5424
EOF

../src/syslogd -m1 -b :${PORT2} -d -sF -f ${CONF} -p ${SOCK2} -p ${ALTSOCK} -P ${PID2} >${LOG2} &
sleep 3
cat ${PID2} >> "$DIR/PIDs"

sleep 1

if grep 'notify '${NOT1} ${LOG2}; then
	:
else
	exit $?
fi

if [ -x ../src/logger ]; then
	:
else
	exit 0
fi

kill -USR1 `cat ${PID2}`

../src/logger -u ${SOCK2} notrotall-1
kill -USR2 `cat ${PID2}`
sleep 1 # XXX async process sync?
if [ -f ${LOG}.0 ] && [ -f ${LOG}X.0 ] &&
		grep notrotall-1 ${LOG}.0 &&
		grep notrotall-1 ${LOG}X.0; then
	:
else
	exit 1
fi

rm -f ${NOT1STAMP}
../src/logger -u ${SOCK2} notrotall-2
kill -USR2 `cat ${PID2}`
sleep 1 # XXX async process sync?
if [ -f ${LOG}.0 ] && [ -f ${LOG}X.0 ] &&
		[ -f ${LOG}.1.gz ] && [ -f ${LOG}X.1.gz ] &&
		grep notrotall-2 ${LOG}.0 &&
		grep notrotall-2 ${LOG}X.0 &&
		zgrep notrotall-1 ${LOG}.1.gz &&
		zgrep notrotall-1 ${LOG}X.1.gz; then
	:
else
	exit 1
fi

rm -f ${NOT1STAMP}
../src/logger -u ${SOCK2} notrotall-3
kill -USR2 `cat ${PID2}`
sleep 1 # XXX async process sync?
if [ -f ${LOG}.0 ] && [ -f ${LOG}X.0 ] &&
		[ -f ${LOG}.1.gz ] && [ -f ${LOG}X.1.gz ] &&
		[ -f ${LOG}.2.gz ] && [ -f ${LOG}X.2.gz ] &&
		grep notrotall-3 ${LOG}.0 &&
		grep notrotall-3 ${LOG}X.0 &&
		zgrep notrotall-2 ${LOG}.1.gz &&
		zgrep notrotall-2 ${LOG}X.1.gz &&
		zgrep notrotall-1 ${LOG}.2.gz &&
		zgrep notrotall-1 ${LOG}X.2.gz; then
	:
else
	exit 1
fi

kill -9 `cat ${PID2}`

sleep 1 # XXX synchronization of async process?
if [ -f ${LOG}.0 ] && grep 'script 1' ${NOT1STAMP}; then
	:
else
	exit 1
fi
