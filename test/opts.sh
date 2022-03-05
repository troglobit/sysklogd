#!/bin/sh
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

cat <<EOF > ${CONF}
# Match all log messages, store in RC5424 format and rotate every 10 MiB
*.*       -${LOG}    ;rotate=10M:5,RFC5424
EOF

setup -m0 >"${LOG2}"

grep ';RFC5424,rotate=10000000:5' ${LOG2} || FAIL "Failed parsing RFC542 .conf"
