/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)syslog.c	5.28 (Berkeley) 6/27/90";
#endif /* LIBC_SCCS and not lint */

/*
 * SYSLOG -- print message on log file
 *
 * This routine looks a lot like printf, except that it outputs to the
 * log file instead of the standard output.  Also:
 *	adds a timestamp,
 *	prints the module name in front of the message,
 *	has some other formatting types (or will sometime),
 *	adds a newline on the end of the message.
 *
 * The output of this routine is intended to be read by syslogd(8).
 *
 * Author: Eric Allman
 * Modified to use UNIX domain IPC by Ralph Campbell
 *
 * Sat Dec 11 11:58:31 CST 1993: Dr. Wettstein
 *	Changes to allow compilation with no complains under -Wall.
 *
 * Thu Jan 18 11:16:11 CST 1996: Dr. Wettstein
 *	Added patch to close potential security hole.  This is the same
 *	patch which was announced in the linux-security mailing lists
 *	and incorporated into the libc version of syslog.c.
 *
 * Sun Mar 11 20:23:44 CET 2001: Martin Schulze <joey@infodrom.ffis.de>
 *	Use SOCK_DGRAM for loggin, renables it to work.	
 *
 * Wed Aug 27 17:48:16 CEST 2003: Martin Schulze <joey@Infodrom.org>
 *	Improved patch by Michael Pomraning <mjp@securepipe.com> to
 *	reconnect klogd to the logger after it went away.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define _PATH_LOGNAME "/dev/log"

#ifndef TESTING
static struct sockaddr SyslogAddr;         /* AF_UNIX address of local logger */
#endif
static int         LogFile = -1;           /* fd for log */
static int         connected;              /* have done connect */
static int         LogStat = 0;            /* status bits, set by openlog() */
static const char *LogTag = "syslog";      /* string to tag the entry with */
static int         LogFacility = LOG_USER; /* default facility code */

void syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

void vsyslog(int pri, const char *fmt, va_list ap)
{
	int    cnt;
	char * p;
	time_t now;
	int    fd, saved_errno;
	int    result;
	char   tbuf[2048], fmt_cpy[1024], *stdp = NULL;

	saved_errno = errno;

	/* see if we should just throw out this message */
	if (!LOG_MASK(LOG_PRI(pri)) || (pri & ~(LOG_PRIMASK | LOG_FACMASK)))
		return;
	if (LogFile < 0 || !connected)
		openlog(LogTag, LogStat | LOG_NDELAY, LogFacility);

	/* set default facility if none specified */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	/* build the message */
	(void)time(&now);
	(void)sprintf(tbuf, "<%d>%.15s ", pri, ctime(&now) + 4);
	for (p = tbuf; *p; ++p)
		;
	if (LogStat & LOG_PERROR)
		stdp = p;
	if (LogTag) {
		(void)strcpy(p, LogTag);
		for (; *p; ++p)
			;
	}
	if (LogStat & LOG_PID) {
		(void)sprintf(p, "[%d]", getpid());
		for (; *p; ++p)
			;
	}
	if (LogTag) {
		*p++ = ':';
		*p++ = ' ';
	}

	/* substitute error message for %m */
	{
		char ch, *t1, *t2;
		char *strerror();

		for (t1 = fmt_cpy;
		     (ch = *fmt) != '\0' && t1 < fmt_cpy + sizeof(fmt_cpy);
		     ++fmt)
			if (ch == '%' && fmt[1] == 'm') {
				++fmt;
				for (t2 = strerror(saved_errno);
				     (*t1 = *t2++); ++t1)
					;
			} else
				*t1++ = ch;
		*t1 = '\0';
	}

	(void)vsprintf(p, fmt_cpy, ap);

	cnt = strlen(tbuf);

	/* output to stderr if requested */
	if (LogStat & LOG_PERROR) {
		struct iovec iov[2];
		struct iovec *v = iov;

		v->iov_base = stdp;
		v->iov_len = cnt - (stdp - tbuf);
		++v;
		v->iov_base = "\n";
		v->iov_len = 1;
		(void)writev(2, iov, 2);
	}

	/* output the message to the local logger */
	result = write(LogFile, tbuf, cnt + 1);

	if (result == -1 && (errno == ECONNRESET || errno == ENOTCONN || errno == ECONNREFUSED)) {
		closelog();
		openlog(LogTag, LogStat | LOG_NDELAY, LogFacility);
		result = write(LogFile, tbuf, cnt + 1);
	}

	if (result >= 0 || !(LogStat & LOG_CONS))
		return;

	/*
	 * output the message to the console; don't worry about
	 * blocking, if console blocks everything will.
	 */
	if ((fd = open(_PATH_CONSOLE, O_WRONLY | O_NOCTTY, 0)) < 0)
		return;
	(void)strcat(tbuf, "\r\n");
	cnt += 2;
	p = index(tbuf, '>') + 1;
	(void)write(fd, p, cnt - (p - tbuf));
	(void)close(fd);
}

/*
 * OPENLOG -- open system log
 */
void openlog(const char *ident, int logstat, int logfac)
{
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;

#ifdef ALLOW_KERNEL_LOGGING
	if ((logfac & ~LOG_FACMASK) == 0)
#else
	if (logfac != 0 && (logfac & ~LOG_FACMASK) == 0)
#endif
		LogFacility = logfac;

#ifndef TESTING
	if (LogFile == -1) {
		SyslogAddr.sa_family = AF_UNIX;
		strncpy(SyslogAddr.sa_data, _PATH_LOGNAME, sizeof(SyslogAddr.sa_data));
		if (LogStat & LOG_NDELAY) {
			LogFile = socket(AF_UNIX, SOCK_DGRAM, 0);
			fcntl(LogFile, F_SETFD, 1); /* FD_CLOEXEC */
		}
	}
	if (LogFile != -1 && !connected &&
	    connect(LogFile, &SyslogAddr, sizeof(SyslogAddr.sa_family) + strlen(SyslogAddr.sa_data)) != -1)
		connected = 1;
#else
	LogFile = fileno(stdout);
	connected = 1;
#endif
}

/*
 * CLOSELOG -- close the system log
 */
void closelog()
{
#ifndef TESTING
	(void)close(LogFile);
#endif
	LogFile = -1;
	connected = 0;
}

static int LogMask = 0xff; /* mask of priorities to be logged */
/*
 * SETLOGMASK -- set the log mask level
 */
int setlogmask(int pmask)
{
	int omask;

	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return omask;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
