/*-
 * SPDX-License-Identifier: Unlicense
 *
 * This is free and unencumbered software released into the public domain.
 *
 * The classic BSD syslog() API: openlog() flags, a priority mask, the
 * %m conversion (expands to strerror(errno)), and an explicit facility
 * OR'ed into the level for a single message.
 */

#include <errno.h>
#include <syslog/syslog.h>

int main(void)
{
	/* LOG_PID tags each line with our PID, LOG_PERROR copies to stderr. */
	openlog("basic", LOG_PID | LOG_PERROR, LOG_DAEMON);

	/* Drop anything less severe than LOG_NOTICE. */
	setlogmask(LOG_UPTO(LOG_NOTICE));

	syslog(LOG_INFO, "filtered out by the priority mask");
	syslog(LOG_NOTICE, "starting up, pid logged automatically");

	/* %m expands to the error string for the current errno. */
	errno = EACCES;
	syslog(LOG_ERR, "cannot open config: %m");

	/* Override the default facility for a single message. */
	syslog(LOG_WARNING | LOG_LOCAL0, "routed to local0 instead of daemon");

	closelog();

	return 0;
}
