#!/bin/sh
# Verify logger parses a leading <LEVEL> (systemd journal style) on
# messages read from stdin, overriding the severity and stripping the
# prefix from the payload, e.g. for 'daemon --foreground 2>&1 | logger'.
# A <LEVEL> in a message given as an argument is left untouched.
#
. "${srcdir:-.}/lib.sh"

LOGDIR="$DIR/log"
ERRLOG="${LOGDIR}/err.log"
INFOLOG="${LOGDIR}/info.log"
NOTICELOG="${LOGDIR}/notice.log"

MSG_ERR="loglevel-err-$$"
MSG_INFO="loglevel-info-$$"
MSG_ARG="loglevel-arg-$$"

setup_syslogd()
{
    [ -x ../src/logger ] || SKIP 'logger missing'

    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	user.=err	-${ERRLOG}
	user.=info	-${INFOLOG}
	user.=notice	-${NOTICELOG}
	EOF
    setup -m0
}

# <3> on stdin overrides -p user.notice -> user.err
verify_stdin_err()
{
    printf '<3>%s\n' "${MSG_ERR}" | ../src/logger -u "${SOCK}" -p user.notice -t lt
    tenacious 5 grep "${MSG_ERR}" "${ERRLOG}"
}

# the <3> prefix must be stripped from the logged payload
verify_prefix_stripped()
{
    grep "<3>" "${ERRLOG}" && return 1
    return 0
}

# <6> on stdin overrides -p user.notice -> user.info
verify_stdin_info()
{
    printf '<6>%s\n' "${MSG_INFO}" | ../src/logger -u "${SOCK}" -p user.notice -t lt
    tenacious 5 grep "${MSG_INFO}" "${INFOLOG}"
}

# a <LEVEL> in an argument message is not parsed: the severity stays
# user.notice and the literal prefix remains in the payload
verify_arg_not_parsed()
{
    ../src/logger -u "${SOCK}" -p user.notice -t lt "<4>${MSG_ARG}"
    tenacious 5 grep "<4>${MSG_ARG}" "${NOTICELOG}"
}

run_step "Set up syslogd with severity filters"     setup_syslogd
run_step "Verify <3> stdin override to err"         verify_stdin_err
run_step "Verify <3> prefix stripped from payload"  verify_prefix_stripped
run_step "Verify <6> stdin override to info"        verify_stdin_info
run_step "Verify <LEVEL> in argument not parsed"    verify_arg_not_parsed
