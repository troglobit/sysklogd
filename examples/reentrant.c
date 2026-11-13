/*-
 * SPDX-License-Identifier: Unlicense
 *
 * This is free and unencumbered software released into the public domain.
 *
 * The reentrant (_r) API.  Each caller keeps its own struct syslog_data
 * instead of the library's shared global, so a library can log without
 * disturbing the host program's openlog() settings.  Initialise it with
 * SYSLOG_DATA_INIT.  LOG_PERROR echoes each message to stderr.
 */

#include <stddef.h>		/* NULL (used by SYSLOG_DATA_INIT) */
#include <syslog/syslog.h>

int main(void)
{
	struct syslog_data sd = SYSLOG_DATA_INIT;

	openlog_r("reentrant", LOG_PID | LOG_PERROR, LOG_USER, &sd);
	setlogmask_r(LOG_UPTO(LOG_INFO), &sd);

	syslog_r(LOG_INFO, &sd, "plain reentrant message");
	syslogp_r(LOG_NOTICE, &sd, "BACKUP",
		  "[exampleSDID@32473 status=\"ok\"]",
		  "backup completed in %d seconds", 42);

	closelog_r(&sd);

	return 0;
}
