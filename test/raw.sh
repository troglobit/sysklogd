#!/bin/sh
. "${srcdir:-.}/lib.sh"

ID47="$DIR/id47.log"
DATA="$DIR/data.log"

setup_rfc5424()
{
    cat <<-EOF > "${CONF}"
	# Match all log messages, store in RC5424
	*.*       -${LOG}    ;RFC5424
	# Match ID47
	:msgid, equal, "ID47"
	*.*       ${ID47}    ;RFC5424
	:data, regex, ".*eventSource=\"Application\".*"
	*.*       ${DATA}    ;RFC5424
	EOF
    setup -m0 >"${LOG2}"
}

verify_netcat()
{
    MSG='<165>1 2003-10-11T22:14:15.003Z mymachine.example.com su 12345 ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][id@2 test="tast"] BOM"su root" failed for lonvick on /dev/pts/8" '

    echo "$MSG" | nc -w1 -Uu "${SOCK}"
    grep -H "mymachine" "${ID47}"
}

check_log()
{
    log="$1"; shift
    msg="$*"

    grep -H "$msg" "$log"
}

run_step "Set up syslogd w/ RFC5424"         setup_rfc5424
run_step "Verify parsing of netcat message"  verify_netcat
run_step "Verify regexp on structured data"  check_log "$DATA" "mymachine"
