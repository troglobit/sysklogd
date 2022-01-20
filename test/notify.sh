#!/bin/sh
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

NOT1=${DIR}/${NM}-1.sh
NOT1STAMP=${DIR}/${NM}-1.stamp
NOT2=${DIR}/${NM}-2.sh
NOT2STAMP=${DIR}/${NM}-2.stamp

printf '#!/bin/sh -\necho script 1: $* > '${NOT1STAMP}'\n' > ${NOT1}
printf '#!/bin/sh -\necho script 2: $* > '${NOT2STAMP}'\n' > ${NOT2}
chmod 0755 ${NOT1} ${NOT2}

cat <<EOF > ${CONF}
notify ${NOT1}
# Match all log messages, store in RC5424 format and rotate every 1 KiB
*.*       -${LOG}    ;rotate=1k:2,RFC5424
notify ${NOT2}
EOF

../src/syslogd -m1 -b :${PORT2} -d -sF -f ${CONF} -p ${SOCK2} -p ${ALTSOCK} -P ${PID2} >${LOG2} &
sleep 3
cat ${PID2} >> "$DIR/PIDs"

if grep 'notify '${NOT1} ${LOG2} && grep 'notify '${NOT2} ${LOG2}; then
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

MSG=01234567890123456789012345678901234567890123456789
MSG=$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG
../src/logger -u ${SOCK2} ${MSG}
../src/logger -u ${SOCK2} 1${MSG}
../src/logger -u ${SOCK2} 2${MSG}

kill -9 `cat ${PID2}`

sleep 1 # XXX synchronization of async process?
if [ -f ${LOG}.0 ] &&
		grep 'script 1' ${NOT1STAMP} &&
		grep 'script 2' ${NOT2STAMP}; then
	:
else
	exit 1
fi
