#!/bin/sh
# Test message to various facilities
# shellcheck disable=SC2317
if [ -z "${srcdir}" ]; then
    srcdir=.
fi
. "${srcdir}/lib.sh"

LOGFILE="${DIR}/sudo.log"
LOGDIR="$DIR/log"
LOGMSG="hey ho here we go"

AUTHMSG="Here is the password: p455w0rd"
AUTHLOG=${LOGDIR}/auth.log

DBGLOG=${LOGDIR}/debug
MSGLOG=${LOGDIR}/messages


setup_facility()
{
    mkdir -p "$LOGDIR"
    install -m 600 /dev/null "${LOGDIR}/auth.log"

    cat <<-EOF >"${CONFD}/facility.conf"
	auth,authpriv.*			$AUTHLOG
	*.*;auth,authpriv.none;\
		local7.!=notice		-${LOGDIR}/syslog
	daemon.*			-${LOGDIR}/daemon.log
	kern.*				-${LOGDIR}/kern.log
	lpr.*				-${LOGDIR}/lpr.log
	mail.*				-${LOGDIR}/mail.log
	user.*				-${LOGDIR}/user.log
	mail.info			-${LOGDIR}/mail.info
	mail.warn			-${LOGDIR}/mail.warn
	mail.err			${LOGDIR}/mail.err
	*.=debug;\
		auth,authpriv.none;\
		news.none;mail.none	-$DBGLOG
	*.=info;*.=notice;*.=warn;\
		auth,authpriv.none;\
		cron,daemon.none;\
		local7.!=notice;\
		mail,news.none		-$MSGLOG
	*.emerg				*
	local7.=notice			$LOGFILE
	EOF
    setup -m0
}

verify_logdir_exists()
{
    ls "$AUTHLOG"	# Must exist
}

# shellcheck disable=SC2012
verify_authlog_perms()
{
    perms=$(ls -l "$AUTHLOG" | tee "$DIR/foo" | awk '{print $1}')
    cat "$DIR/foo"
    test "$perms" = "-rw-------"
}

verify_logfile_exists()
{
    ls "$LOGFILE"	# Must exist
}

verify_logfile()
{
    TAG="facility"

    logger -t $TAG -p local7.notice "${LOGMSG}"
    sleep 1
    grep "$TAG: ${LOGMSG}" "$LOGFILE"
}

# Ensure the dedicated local7.notice message reached no other log file
verify_leaks()
{
    find "$LOGDIR" -type f -exec grep -q "$LOGMSG" {} \; -quit
}

verify_authpriv()
{
    logger -t login -p authpriv.debug "$AUTHMSG"
    grep "$AUTHMSG" "$AUTHLOG"
}

# Ensure $AUTHMSG is only in $AUTHLOG
verify_authleaks()
{
    find "$LOGDIR" -type f ! -wholename "$AUTHLOG" -exec grep -H "$AUTHMSG" {} \; -quit
}

run_step "Set up facility filtering daemon" setup_facility
run_step "Verify log dir exists"            verify_logdir_exists
run_step "Verify auth.log permissions"      verify_authlog_perms
run_step "Verify log file exists"           verify_logfile_exists
run_step "Verify local7.notice log file"    verify_logfile
run_step "Verify no local7 log leaks"       verify_leaks
run_step "Verify authpriv logging"          verify_authpriv
run_step "Verify no authpriv leaks"         verify_authleaks
