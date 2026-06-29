/*-
 * SPDX-License-Identifier: Unlicense
 *
 * This is free and unencumbered software released into the public domain.
 *
 * syslogp() with an RFC5424 MSGID and a structured-data (SD) element.
 * The msgid, sdfmt, and msgfmt arguments are all printf-style; here the
 * message takes one (%s) argument while the MSGID and SD are literal.
 *
 * The MSGID and SD travel in the RFC5424 frame sent to syslogd.  To
 * record them, point syslogd at an RFC5424 destination (see
 * syslog.conf(5)):
 *
 *     local0.*    /var/log/app.log    ;RFC5424
 *
 * which yields a line like:
 *
 *     <133>1 TIMESTAMP HOST structured PID TLSEVENT \
 *         [exampleSDID@32473 iut="3" eventSource="Application"] \
 *         connection accepted from 10.0.0.7
 *
 * LOG_PERROR additionally echoes the message text to stderr.  Use a
 * registered IANA Private Enterprise Number for your own SD-IDs; 32473
 * is the documentation/example PEN from RFC 5612.
 */

#include <syslog/syslog.h>

int main(void)
{
	const char *msgid = "TLSEVENT";
	const char *sd    = "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\"]";

	openlog("structured", LOG_PID | LOG_PERROR, LOG_LOCAL0);
	syslogp(LOG_NOTICE, msgid, sd, "connection accepted from %s", "10.0.0.7");
	closelog();

	return 0;
}
