#!/bin/sh
if [ -z "${srcdir}" ]; then
    srcdir=.
fi
. "${srcdir}/lib.sh"

setup_debug()
{
    DEBUG=true

    cat <<-EOF > "${CONF}"
	# Match all log messages, store in RC5424 format and rotate every 10 MiB
	*.*       -${LOG}    ;rotate=10M:5,RFC5424
	EOF
    setup -m0 >"${LOG2}"
}

verify_log_parse()
{
    grep ';RFC5424,rotate=10000000:5' "${LOG2}"
}

run_step "Set up syslogd w/ log rotation and RFC5424" setup_debug
run_step "Verify correct parsing of log options"      verify_log_parse
