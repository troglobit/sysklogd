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
