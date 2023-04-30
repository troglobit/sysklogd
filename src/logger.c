/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018-2023  Joachim Wiberg <troglobit@gmail.com>
 * All rights reserved.
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
 */

#include "config.h"

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SYSLOG_NAMES
#include "compat.h"
#include "syslog.h"

static const char version_info[] = PACKAGE_NAME " v" PACKAGE_VERSION;
static struct syslog_data log    = SYSLOG_DATA_INIT;

static int create(char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return mknod(path, S_IFREG | mode, 0) || chown(path, uid, gid);
}

/*
 * This function triggers a log rotates of @file when size >= @sz bytes
 * At most @num old versions are kept and by default it starts gzipping
 * .2 and older log files.  If gzip is not available in $PATH then @num
 * files are kept uncompressed.
 */
static int logrotate(char *file, int num, off_t sz)
{
	struct stat st;
	int cnt;

	if (stat(file, &st))
		return 1;

	if (sz > 0 && S_ISREG(st.st_mode) && st.st_size > sz) {
		if (num > 0) {
			size_t len = strlen(file) + 10 + 1;
			char   ofile[len];
			char   nfile[len];

			/* First age zipped log files */
			for (cnt = num; cnt > 2; cnt--) {
				snprintf(ofile, len, "%s.%d.gz", file, cnt - 1);
				snprintf(nfile, len, "%s.%d.gz", file, cnt);

				/* May fail because ofile doesn't exist yet, ignore. */
				(void)rename(ofile, nfile);
			}

			for (cnt = num; cnt > 0; cnt--) {
				snprintf(ofile, len, "%s.%d", file, cnt - 1);
				snprintf(nfile, len, "%s.%d", file, cnt);

				/* May fail because ofile doesn't exist yet, ignore. */
				(void)rename(ofile, nfile);

				if (cnt == 2 && !access(nfile, F_OK)) {
					size_t len = 5 + strlen(nfile) + 1;
					char cmd[len];

					snprintf(cmd, len, "gzip %s", nfile);
					system(cmd);

					remove(nfile);
				}
			}

			if (rename(file, nfile))
				(void)truncate(file, 0);
			else
				create(file, st.st_mode, st.st_uid, st.st_gid);
		} else {
			if (truncate(file, 0))
				syslog(LOG_ERR | LOG_PERROR, "Failed truncating %s during logrotate: %s", file, strerror(errno));
		}
	}

	return 0;
}

static void log_kmsg(FILE *fp, char *ident, int pri, int opts, char *buf)
{
	while (isspace(*buf))
		buf++;

	/* Always add [PID] so syslogd can find this later on */
	fprintf(fp, "<%d>%s[%d]:%s\n", pri, ident, getpid(), buf);
}

static int nslookup(const char *host, const char *svcname, int family, struct sockaddr *sa)
{
	struct addrinfo hints, *ai, *result;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags    = !host ? AI_PASSIVE : 0;
	hints.ai_family   = family;
	hints.ai_socktype = SOCK_DGRAM;

	error = getaddrinfo(host, svcname, &hints, &result);
	if (error == EAI_SERVICE) {
		warnx("%s/udp: unknown service, trying syslog port 514", svcname);
		svcname = "514";
		error = getaddrinfo(host, svcname, &hints, &result);
	}
	if (error) {
		warnx("%s (%s:%s)", gai_strerror(error), host, svcname);
		return 1;
	}

	for (ai = result; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;

		memcpy(sa, ai->ai_addr, ai->ai_addrlen);
		break;
	}
	freeaddrinfo(result);

	return 0;
}

static int checksz(FILE *fp, off_t sz)
{
	struct stat st;

	if (!fp)
		return 0;

	fsync(fileno(fp));
	if (sz <= 0)
		return 0;

	if (!fstat(fileno(fp), &st) && st.st_size > sz) {
		fclose(fp);
		return 1;
	}

	return 0;
}

static char *chomp(char *str)
{
        char *p;

        if (!str || strlen(str) < 1) {
                errno = EINVAL;
                return NULL;
        }

        p = str + strlen(str) - 1;
        while (p >= str && *p == '\n')
                *p-- = 0;

        return str;
}

static int parse_prio(char *arg, int *f, int *l)
{
	char *ptr;

	ptr = strchr(arg, '.');
	if (ptr) {
		*ptr++ = 0;

		for (int i = 0; facilitynames[i].c_name; i++) {
			if (strcmp(facilitynames[i].c_name, arg))
				continue;

			*f = facilitynames[i].c_val;
			break;
		}

		arg = ptr;
	}

	for (int i = 0; prioritynames[i].c_name; i++) {
		if (strcmp(prioritynames[i].c_name, arg))
			continue;

		*l = prioritynames[i].c_val;
		break;
	}

	return 0;
}

static int usage(int code)
{
	printf("Usage: logger [OPTIONS] [MESSAGE]\n"
	       "\n"
	       "Write MESSAGE (or line-by-line stdin) to syslog, or file (with logrotate).\n"
	       "\n"
	       "  -4        Prefer IPv4 address when sending remote, see -h\n"
	       "  -6        Prefer IPv6 address when sending remote, see -h\n"
	       "  -b        Use RFC3164 (BSD) style format, default: RFC5424\n"
	       "  -c        Log to console (LOG_CONS) on failure\n"
	       "  -d SD     Log SD as RFC5424 style 'structured data' in message\n"
	       "  -f FILE   Log file to write messages to, instead of syslog daemon\n"
	       "  -h HOST   Send (UDP) message to this remote syslog server (IP or DNS name)\n"
	       "  -H NAME   Use NAME instead of system hostname in message header\n"
	       "  -i        Log process ID of the logger process with each line (LOG_PID)\n"
	       "  -I PID    Log process ID using PID, recommed using PID $$ for shell scripts\n"
#ifdef __linux__
	       "  -k        Log to kernel /dev/kmsg if /dev/log doesn't exist yet\n"
#endif
	       "  -m MSGID  Log message using this RFC5424 style MSGID\n"
	       "  -n        Open log file immediately (LOG_NDELAY)\n"
	       "  -p PRIO   Log message priority (numeric or facility.severity pair)\n"
	       "  -P PORT   Use PORT (or named UDP service) for remote server, default: syslog\n"
	       "  -r S[:R]  Enable log file rotation, default: 200 kB \e[4ms\e[0mize, 5 \e[4mr\e[0motations\n"
	       "  -s        Log to stderr as well as the system log\n"
	       "  -t TAG    Log using the specified tag (defaults to user name)\n"
	       "  -u SOCK   Log to UNIX domain socket `SOCK` instead of default %s\n"
	       "  -?        This help text\n"
	       "  -v        Show program version\n"
	       "\n"
	       "Bug report address: %s\n", _PATH_LOG, PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
	printf("Project home page:  %s\n", PACKAGE_URL);
#endif

	return code;
}

int main(int argc, char *argv[])
{
	char *ident = NULL, *logfile = NULL;
	char *host = NULL, *sockpath = NULL;
	char *msgid = NULL, *sd = NULL;
	char *svcname = "syslog";
	off_t size = 200 * 1024;
	int facility = LOG_USER;
	int severity = LOG_NOTICE;
	int family = AF_UNSPEC;
	struct sockaddr sa;
	int allow_kmsg = 0;
	char buf[512] = "";
	int log_opts = 0;
	FILE *fp = NULL;
	int c, num = 5;
	int rotate = 0;

	while ((c = getopt(argc, argv, "46?bcd:f:h:H:iI:km:np:P:r:st:u:v")) != EOF) {
		switch (c) {
		case '4':
			family = AF_INET;
			break;

		case '6':
			family = AF_INET6;
			break;

		case 'b':
			log_opts |= LOG_RFC3164;
			break;

		case 'c':
			log_opts |= LOG_CONS;
			break;

		case 'd':
			sd = optarg;
			break;

		case 'f':
			logfile = optarg;
			break;

		case 'h':
			host = optarg;
			break;

		case 'H':
			strlcpy(log.log_hostname, optarg, sizeof(log.log_hostname));
			break;

		case 'i':
			log_opts |= LOG_PID;
			break;

		case 'I':
			log_opts |= LOG_PID;
			log.log_pid = atoi(optarg);
			break;

		case 'k':
#ifdef __linux__
			allow_kmsg = 1;
#else
			errx(1, "-k is not supported on non-Linux systems.");
#endif
			break;

		case 'm':
			msgid = optarg;
			break;

		case 'n':
			log_opts |= LOG_NDELAY;
			break;

		case 'p':
			if (parse_prio(optarg, &facility, &severity))
				return usage(1);
			break;

		case 'P':
			svcname = optarg;
			break;

		case 'r':
			parse_rotation(optarg, &size, &num);
			if (size > 0 && num > 0)
				rotate = 1;
			break;

		case 's':
			log_opts |= LOG_PERROR;
			break;

		case 't':
			ident = optarg;
			break;

		case 'u':
			sockpath = optarg;
			break;

		case 'v':	/* version */
			printf("%s\n", version_info);
			return 0;

		default:
			return usage(0);
		}
	}

	if (!ident)
		ident = getenv("LOGNAME") ?: getenv("USER");

	if (optind < argc) {
		size_t pos = 0, len = sizeof(buf);

		while (optind < argc) {
			size_t bytes;

			bytes = snprintf(&buf[pos], len, "%s%s", pos ? " " : "", argv[optind++]);
			pos += bytes;
			len -= bytes;
		}
	}

	if (logfile) {
		if (strcmp(logfile, "-")) {
			log_opts |= LOG_NLOG;
			fp = fopen(logfile, "a");
			if (!fp)
				err(1, "Failed opening %s for writing", logfile);
		} else {
			log_opts |= LOG_STDOUT;
			fp = stdout;
		}

		log.log_file = fileno(fp);
	} else if (sockpath) {
		if (access(sockpath, W_OK))
			err(1, "Socket path %s", sockpath);
		log.log_sockpath = sockpath;
	} else if (allow_kmsg && access(_PATH_LOG, W_OK)) {
		/*
		 * -k and /dev/log is not yet up, user wants to prevent
		 * logging to console and instead use the detour around
		 * the kernel logger until syslogd has started.
		 */
		while (!access("/dev/kmsg", W_OK)) {
			int pri = facility | severity;

			fp = fopen("/dev/kmsg", "w");
			if (!fp)
				break;	/* fall back to log syslogp_r() */

			if (!buf[0]) {
				while ((fgets(buf, sizeof(buf), stdin)))
					log_kmsg(fp, ident, pri, log_opts, chomp(buf));
			} else
				log_kmsg(fp, ident, pri, log_opts, buf);

			return fclose(fp);
		}
	} else if (host) {
		log.log_host = &sa;
		if (nslookup(host, svcname, family, &sa))
			return 1;
		log_opts |= LOG_NDELAY;
	}

	openlog_r(ident, log_opts, facility, &log);

	if (!buf[0]) {
		while ((fgets(buf, sizeof(buf), stdin)))
			syslogp_r(severity, &log, msgid, sd, "%s", chomp(buf));
	} else
		syslogp_r(severity, &log, msgid, sd, "%s", buf);

	closelog_r(&log);

	if (logfile && rotate && checksz(fp, size))
		logrotate(logfile, num, size);

	return 0;
}

