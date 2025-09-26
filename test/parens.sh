#!/bin/sh
# Verify parentheses handling in log tags for RFC3164 messages.
# Regression test for issue #104.
#
. "${srcdir:-.}/lib.sh"


MSG1="Failed to execute /usr/bin/pkttyagent: No such file or directory"
MSG2="Normal application message"
MSG3="Version specific message"
MSG4="Service startup message"

LOGDIR="$DIR/log"
SYSLOG="${LOGDIR}/syslog"

setup_syslogd()
{
    mkdir -p "$LOGDIR"
    cat <<-EOF >"${CONF}"
	# Log everything for testing
	*.*		-$SYSLOG
	EOF
    setup -m0
}


extract_tag()
{
    msg="$1"
    actual_line=$(grep "$msg" "$SYSLOG" | tail -1)
    if [ -n "$actual_line" ]; then
        echo "$actual_line" | sed -n 's/.*[0-9][0-9] [^ ]* \([^:]*\):.*/\1/p'
    fi
}

show_result()
{
    input="$1"
    expected="$2"
    got="$3"

    echo "Input:    '$input'"
    echo "Expected: '$expected'"
    echo "Got:      '$got'"
}

verify()
{
    input_tag="$1"
    expected_tag="$2"
    msg="$3"
    expected_pattern="${4:-$expected_tag}"

    actual_tag=$(extract_tag "$msg")
    if [ -n "$actual_tag" ]; then
        show_result "$input_tag" "$expected_tag" "$actual_tag"
        if grep -q "$expected_pattern.*$msg" "$SYSLOG"; then
            return 0
        else
            echo "Log contents:"
            cat "$SYSLOG"
            return 1
        fi
    else
        echo "Message not found in log"
        echo "Log contents:"
        cat "$SYSLOG"
        return 1
    fi
}

test_normal_tag()
{
    logger -b -ip user.info -t "normal-app" "$MSG2"
    verify "normal-app" "normal-app" "$MSG2"
}

test_paren_stripping()
{
    logger -b -ip user.info -t "(polkit-agent)" "$MSG1"
    verify "(polkit-agent)" "polkit-agent" "$MSG1"
}

test_service_stripping()
{
    logger -b -ip user.info -t "(service-name)" "$MSG4"
    verify "(service-name)" "service-name" "$MSG4"
}

test_partial_parens()
{
    logger -b -ip user.info -t "app(version)" "$MSG3"
    verify "app(version)" "app(version)" "$MSG3"
}

test_normal_tag_with_pid()
{
    pid="$$"

    logger -b -ip user.info -t "normal-app[${pid}]" "$MSG2"
    verify "normal-app[${pid}]" "normal-app[${pid}]" "$MSG2" "normal-app\[${pid}\]"
}

test_paren_with_pid()
{
    pid="$$"

    logger -b -ip user.info -t "(polkit-agent)[$pid]" "$MSG1"
    verify "(polkit-agent)[$pid]" "polkit-agent[$pid]" "$MSG1" "polkit-agent\[$pid\]"
}


run_step "Set up syslogd for parentheses testing" setup_syslogd
run_step "Test parenthetical tag stripping" test_paren_stripping
run_step "Test normal tag preservation" test_normal_tag
run_step "Test partial parentheses preservation" test_partial_parens
run_step "Test service parenthetical tag" test_service_stripping
run_step "Test parenthetical tag with PID" test_paren_with_pid
run_step "Test normal tag with PID" test_normal_tag_with_pid
