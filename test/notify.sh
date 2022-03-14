#!/bin/sh
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

[ -x ../src/logger ] || SKIP 'logger missing'

NOT1=${DIR}/${NM}-1.sh
NOT1STAMP=${DIR}/${NM}-1.stamp
NOT2=${DIR}/${NM}-2.sh
NOT2STAMP=${DIR}/${NM}-2.stamp

printf '#!/bin/sh -\necho script 1: $* > '${NOT1STAMP}'\n' > ${NOT1}
printf '#!/bin/sh -\necho script 2: $* > '${NOT2STAMP}'\n' > ${NOT2}
chmod 0755 ${NOT1} ${NOT2}

cat <<EOF > ${CONFD}/notifier.conf
notify      ${NOT1}
# Match all log messages, store in RC5424 format and rotate every 1 KiB
*.*       -${LOG}    ;rotate=1k:2,RFC5424
notify ${NOT2}
EOF

setup

MSG=01234567890123456789012345678901234567890123456789
MSG=$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG
../src/logger -u ${SOCK} ${MSG}
../src/logger -u ${SOCK} 1${MSG}
../src/logger -u ${SOCK} 2${MSG}

if [ -f ${LOG}.0 ] &&
		grep 'script 1' ${NOT1STAMP} &&
		grep 'script 2' ${NOT2STAMP}; then
	OK
else
	FAIL 'Notifier did not run.'
fi
