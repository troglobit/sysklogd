#!/bin/sh
# shellcheck disable=SC1090
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

[ -x ../src/logger ] || SKIP 'logger missing'
command -v zgrep >/dev/null 2>&1 || SKIP 'zgrep(1) missing'

NOT1=${DIR}/${NM}-1.sh
NOT1STAMP=${DIR}/${NM}-1.stamp
NOT2=${DIR}/${NM}-2.sh
NOT2STAMP=${DIR}/${NM}-2.stamp

printf '#!/bin/sh -\necho script 1: $* >> '${NOT1STAMP}'\n' > ${NOT1}
chmod 0755 ${NOT1}

cat <<EOF > ${CONFD}/rotate_all.conf
notify ${NOT1}
*.*       -${LOG}    ;rotate=10k:2,RFC5424
*.*       -${LOG}X   ;rotate=10k:2,RFC5424
EOF

setup

rm -f ${NOT1STAMP}
logger notrotall-1

kill -USR2 `cat ${PID}`
sleep 3
if [ -f ${LOG}.0 ] && [ -f ${LOG}X.0 ] &&
		grep notrotall-1 ${LOG}.0 &&
		grep notrotall-1 ${LOG}X.0; then
	:
else
	FAIL 'Missing log entries, I.'
fi
if [ -f ${NOT1STAMP} ] && grep 'script 1' ${NOT1STAMP} &&
		grep ${LOG} ${NOT1STAMP} && grep ${LOG}X ${NOT1STAMP}; then
	:
else
	FAIL 'Notifier did not run, I.'
fi

rm -f ${NOT1STAMP}
logger notrotall-2

kill -USR2 `cat ${PID}`
sleep 3
if [ -f ${LOG}.0 ] && [ -f ${LOG}X.0 ] &&
		[ -f ${LOG}.1.gz ] && [ -f ${LOG}X.1.gz ] &&
		grep notrotall-2 ${LOG}.0 &&
		grep notrotall-2 ${LOG}X.0 &&
		zgrep notrotall-1 ${LOG}.1.gz &&
		zgrep notrotall-1 ${LOG}X.1.gz; then
	:
else
	FAIL 'Missing log entries, II.'
fi
if [ -f ${NOT1STAMP} ] && grep 'script 1' ${NOT1STAMP} &&
		grep ${LOG} ${NOT1STAMP} && grep ${LOG}X ${NOT1STAMP}; then
	:
else
	FAIL 'Notifier did not run, II.'
fi

cp $NOT1STAMP /tmp/
rm -f ${NOT1STAMP}
logger notrotall-3

kill -USR2 `cat ${PID}`
sleep 3
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
	FAIL 'Missing log entries, III.'
fi
if [ -f ${NOT1STAMP} ] && grep 'script 1' ${NOT1STAMP} &&
		grep ${LOG} ${NOT1STAMP} && grep ${LOG}X ${NOT1STAMP}; then
	:
else
	FAIL 'Notifier did not run, III.'
fi

OK
