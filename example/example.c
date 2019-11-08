/*-
 * SPDX-License-Identifier: Unlicense
 *
 * This is free and unencumbered software released into the public domain.
 */

/* Example of how to use NetBSD syslogp() API with libsyslog from sysklogd */

#include <stdio.h>
#include <syslog/syslog.h>

int main(void)
{
        openlog("example", LOG_PID, LOG_USER);
        syslogp(LOG_NOTICE, "MSGID", NULL, "Kilroy was here.");
	closelog();

	return 0;
}
