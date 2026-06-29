/*-
 * SPDX-License-Identifier: Unlicense
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Minimal example of the sysklogd syslogp() API.  The msgid and SD
 * arguments are NULL here, so this behaves like a plain syslog() call.
 * The message is sent to the local syslogd; LOG_PERROR also echoes it to
 * stderr, so you see output when running this from a terminal.
 */

#include <stddef.h>		/* NULL */
#include <syslog/syslog.h>

int main(void)
{
	openlog("example", LOG_PID | LOG_PERROR, LOG_USER);
	syslogp(LOG_NOTICE, NULL, NULL, "Kilroy was here.");
	closelog();

	return 0;
}
