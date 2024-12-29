#!/bin/sh
if [ -z "${srcdir}" ]; then
    srcdir=.
fi
. "${srcdir}/lib.sh"

NOT1=${DIR}/${NM}-1.sh
NOT2=${DIR}/${NM}-2.sh
NOT1STAMP=${DIR}/${NM}-1.stamp
NOT2STAMP=${DIR}/${NM}-2.stamp

# shellcheck disable=SC2059
setup_notifiers()
{
    printf "#!/bin/sh -\necho script 1: \$* >${NOT1STAMP}\n" >"${NOT1}"
    printf "#!/bin/sh -\necho script 2: \$* >${NOT2STAMP}\n" >"${NOT2}"
    chmod 0755 "${NOT1}" "${NOT2}"
}

# Match all log messages, store in RC5424 format and rotate every 1 KiB
setup_syslogd()
{
    cat <<-EOF > "${CONFD}/notifier.conf"
	notify     ${NOT1}
	*.*       -${LOG}    ;rotate=1k:2,RFC5424
	notify     ${NOT2}
	EOF
    setup -m0
}

trigger_rotation()
{
    MSG=01234567890123456789012345678901234567890123456789
    MSG=$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG$MSG

    logger "${MSG}"
    logger "1${MSG}"
    logger "2${MSG}"

    sleep 1			# Wait for any OS delays
}

verify_rotation()
{
    ls -l "${LOG}.0"
}

verify_notifiers()
{
    grep "script 1: $LOG" "${NOT1STAMP}" \
	&& grep "script 2: $LOG" "${NOT2STAMP}"
}

run_step "Create notifier scripts"       setup_notifiers
run_step "Set up syslogd with notifiers" setup_syslogd
run_step "Trigger log rotation"          trigger_rotation
run_step "Verify log rotation"           verify_rotation
run_step "Verify notifiers have run"     verify_notifiers
