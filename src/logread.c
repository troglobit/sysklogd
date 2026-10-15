/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2024  Joachim Wiberg <troglobit@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * logread -- read syslogd's in-memory log buffer, BusyBox/OpenWRT style.
 */

#include "config.h"

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "compat.h"
#include "membuf.h"

static int usage(int code)
{
	printf("Usage: logread [-fhv] [-e PATTERN] [-u PATH]\n"
	       "\n"
	       "Options:\n"
	       "  -e PATTERN  Only show lines containing PATTERN\n"
	       "  -f          Follow, keep printing new messages as they arrive\n"
	       "  -h          This help text\n"
	       "  -u PATH     syslogd control socket (default: %s)\n"
	       "  -v          Show program version\n", _PATH_MEMBUF);

	return code;
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sun = { 0 };
	const char *path = _PATH_MEMBUF;
	const char *pattern = NULL;
	const char *cmd;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	int follow = 0;
	int c, sd;
	FILE *fp;

	while ((c = getopt(argc, argv, "e:fhu:v")) != EOF) {
		switch (c) {
		case 'e':
			pattern = optarg;
			break;
		case 'f':
			follow = 1;
			break;
		case 'h':
			return usage(0);
		case 'u':
			path = optarg;
			break;
		case 'v':
			puts(PACKAGE_NAME " v" PACKAGE_VERSION);
			return 0;
		default:
			return usage(1);
		}
	}

	sd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sd < 0)
		err(1, "Failed creating socket");

	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (connect(sd, (struct sockaddr *)&sun, sizeof(sun)))
		err(1, "Failed connecting to syslogd at %s", path);

	cmd = follow ? "follow\n" : "dump\n";
	if (write(sd, cmd, strlen(cmd)) < 0)
		err(1, "Failed sending command to syslogd");

	fp = fdopen(sd, "r");
	if (!fp)
		err(1, "Failed reading from syslogd");

	while ((len = getline(&line, &cap, fp)) > 0) {
		if (pattern && !strstr(line, pattern))
			continue;
		fputs(line, stdout);
		if (follow)
			fflush(stdout);	/* show live lines promptly */
	}

	free(line);
	fclose(fp);

	return 0;
}
