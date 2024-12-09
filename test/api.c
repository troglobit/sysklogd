/*
 * Without any options the standard syslog(3) API is used with severity
 * LOG_NOTICE without calling openlog(), so the default LOG_USER facility
 * is used.
 *
 * Options:
 *  -i ID   Log using the given identity to LOG_CONSOLE, calls openlog()
 *  -l      Set logmask to LOG_NOTICE and log with LOG_INFO
 *  -p      Use modern syslogp() API and log to LOG_FTP, use with -i ID
 *
 * See the -i option for made-easy 'grep' check of the log.
 *
 * When the -l option is used, setlogmask() is set to LOG_NOTICE and the
 * LOG_CONSOLE facility is used for logging.  The latter is a sysklogd
 * (BSD) specific facility.
 *
 * The -p option triggers the use of the modern syslogp() API and sets
 * the facility to LOG_FTP.
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "syslog.h"

int main(int argc, char *argv[])
{
	char *ident = NULL;
	char *msg = getenv("MSG");
	char c;
	int severity = LOG_NOTICE;
	int facility = LOG_CONSOLE;
	int v1 = 0;

	if (!msg)
		return 1;

	while ((c = getopt(argc, argv, "i:lp")) != EOF) {
		switch (c) {
		case 'i':
			ident = optarg;
			break;

		case 'l':
			setlogmask(LOG_UPTO(severity));
			severity = LOG_INFO;
			break;

		case 'p':
			v1 = 1;
			facility = LOG_FTP;
			break;
		}
	}

	if (ident)
		openlog(ident, LOG_NOWAIT, facility);

	if (v1)
		syslogp(severity, "MSGID", NULL, "%s", msg);
	else
		syslog(severity, "%s", msg);

	if (ident)
		closelog();

	return 0;
}
