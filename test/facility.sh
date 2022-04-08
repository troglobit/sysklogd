#!/bin/sh
# Test message to various facilities
if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

setup -m0

MSG="hey ho here we go"

cat <<EOF >"${CONFD}/facility.conf"
auth,authpriv.*			${DIR}/auth.log
*.*;auth,authpriv.none;local7.!=notice		-${DIR}/syslog
daemon.*			-${DIR}/daemon.log
kern.*				-${DIR}/kern.log
lpr.*				-${DIR}/lpr.log
mail.*				-${DIR}/mail.log
user.*				-${DIR}/user.log
mail.info			-${DIR}/mail.info
mail.warn			-${DIR}/mail.warn
mail.err			${DIR}/mail.err
*.=debug;\
	auth,authpriv.none;\
	news.none;mail.none	-${DIR}/debug
*.=info;*.=notice;*.=warn;\
	auth,authpriv.none;\
	cron,daemon.none;\
	local7.!=notice;\
	mail,news.none		-${DIR}/messages
*.emerg				:omusrmsg:*
local7.=notice			${DIR}/sudo.log
EOF

reload

print "TEST: Starting"

../src/logger -t facility -p local7.notice -u "${SOCK}" "${MSG}"
sleep 1
grep "${MSG}" "${DIR}/sudo.log" || FAIL ""

OK
