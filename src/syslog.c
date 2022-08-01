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
#if 0
static char sccsid[] = "@(#)syslog.c	8.5 (Berkeley) 4/29/95";
#else
__RCSID("$NetBSD: syslog.c,v 1.55 2015/10/26 11:44:30 roy Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "syslog.h"
#include "compat.h"

static struct syslog_data sdata = SYSLOG_DATA_INIT;

static void	openlog_unlocked_r(const char *, int, int,
    struct syslog_data *);
static void	disconnectlog_r(struct syslog_data *);
static void	connectlog_r(struct syslog_data *);

static mutex_t	syslog_mutex = MUTEX_INITIALIZER;

/*
 * wrapper to catch GLIBC syslog(), which provides this for security measures
 * Note: we only enter here if user includes GLIBC syslog.h
 */
void
__syslog_chk(int pri, int flag __attribute__((unused)), const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

/*
 * Used to determine file/socket type of log_file
 */
static int
is_socket(int fd)
{
	struct stat st;

	if (fstat(fd, &st) || !S_ISSOCK(st.st_mode))
		return 0;

	return 1;
}

/*
 * Used on systems that don't have sa->sa_len
 */
#ifndef HAVE_SA_LEN
static socklen_t sa_len(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET6)
		return sizeof(struct sockaddr_in6);
	if (sa->sa_family == AF_INET)
		return sizeof(struct sockaddr_in);
	return 0;
}
#endif

/*
 * syslog, vsyslog --
 *	print message on log file; output is intended for syslogd(8).
 */
void
syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

void
vsyslog(int pri, const char *fmt, va_list ap)
{
	vsyslog_r(pri, &sdata, fmt, ap);
}

/*
 * syslogp, vsyslogp --
 *	like syslog but take additional arguments for MSGID and SD
 */
void
syslogp(int pri, const char *msgid, const char *sdfmt, const char *msgfmt, ...)
{
	va_list ap;

	va_start(ap, msgfmt);
	vsyslogp(pri, msgid, sdfmt, msgfmt, ap);
	va_end(ap);
}

void
vsyslogp(int pri, const char *msgid, const char *sdfmt, const char *msgfmt, va_list ap)
{
	vsyslogp_r(pri, &sdata, msgid, sdfmt, msgfmt, ap);
}

void
openlog(const char *ident, int logstat, int logfac)
{
	openlog_r(ident, logstat, logfac, &sdata);
}

void
closelog(void)
{
	closelog_r(&sdata);
}

/* setlogmask -- set the log mask level */
int
setlogmask(int pmask)
{
	return setlogmask_r(pmask, &sdata);
}

/* Reentrant version of syslog, i.e. syslog_r() */

void
syslog_r(int pri, struct syslog_data *data, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog_r(pri, data, fmt, ap);
	va_end(ap);
}

void
syslogp_r(int pri, struct syslog_data *data, const char *msgid,
	const char *sdfmt, const char *msgfmt, ...)
{
	va_list ap;

	va_start(ap, msgfmt);
	vsyslogp_r(pri, data, msgid, sdfmt, msgfmt, ap);
	va_end(ap);
}

void
vsyslog_r(int pri, struct syslog_data *data, const char *fmt, va_list ap)
{
	vsyslogp_r(pri, data, NULL, NULL, fmt, ap);
}

void
vsyslogp_r(int pri, struct syslog_data *data, const char *msgid,
	const char *sdfmt, const char *msgfmt, va_list ap)
{
	static const char BRCOSP[] = "]: ";
	static const char CRLF[] = "\r\n";
	struct sockaddr *sa = NULL;
	socklen_t len = 0;
	size_t cnt, prlen, tries;
	char ch, *p, *t;
	struct timeval tv;
	struct tm tmnow;
	time_t now;
	int fd, saved_errno;
#define TBUF_LEN	2048
#define FMT_LEN		1024
#define MAXTRIES	10
	char tbuf[TBUF_LEN], fmt_cpy[FMT_LEN], fmt_cat[FMT_LEN] = "";
	size_t tbuf_left, fmt_left, msgsdlen;
	char *fmt = fmt_cat;
	char dbuf[30];
	struct iovec iov[8];	/* date/time + prog + [ + pid + ]: + fmt + crlf */
	int iovcnt = 0;
	int opened = 0;

#define INTERNALLOG	LOG_ERR|LOG_CONS|LOG_PERROR|LOG_PID
	/* Check for invalid bits. */
	if (pri & ~(LOG_PRIMASK|LOG_FACMASK)) {
		syslog_r(INTERNALLOG, data,
		    "syslog_r: unknown facility/priority: %x", pri);
		pri &= LOG_PRIMASK|LOG_FACMASK;
	}

	/* Check priority against setlogmask values. */
	if (!(LOG_MASK(LOG_PRI(pri)) & data->log_mask))
		return;

	saved_errno = errno;

	/* Set default facility if none specified. */
	if ((pri & LOG_FACMASK) == 0)
		pri |= data->log_fac;

	/* Get system time, wallclock, fall back to UNIX time */
	if (gettimeofday(&tv, NULL) == -1) {
		tv.tv_sec  = time(NULL);
		tv.tv_usec = 0;
	}

	/* strftime() implies tzset(), localtime_r() doesn't. */
	tzset();
	now = (time_t) tv.tv_sec;
	localtime_r(&now, &tmnow);

	/* Build the message. */
	p = tbuf;
	tbuf_left = TBUF_LEN;

#define DEC()							\
	do {							\
		if (prlen >= tbuf_left)				\
			prlen = tbuf_left - 1;			\
		p += prlen;					\
		tbuf_left -= prlen;				\
	} while (/*CONSTCOND*/0)

	/* Default log format is RFC5424, continues below BSD format */
	if (data->log_stat & LOG_RFC3164) {
		const char *tag = data->log_tag;
		char tmp[33];

		if (!(data->log_stat & LOG_NLOG)) {
			prlen = snprintf(p, tbuf_left, "<%d>", pri);
			DEC();
		} else
			prlen = 0;

		prlen = strftime(dbuf, sizeof(dbuf), "%b %d %T ", &tmnow);

		if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
			iov[iovcnt].iov_base = dbuf;
			iov[iovcnt].iov_len = strlen(dbuf);
			iovcnt++;
		}
		if (data->log_host) {
			memcpy(p, dbuf, prlen);
			DEC();
		}

		if (data->log_hostname[0] == '\0' && gethostname(data->log_hostname,
					sizeof(data->log_hostname)) == -1) {
			/* can this really happen? */
			data->log_hostname[0] = '-';
			data->log_hostname[1] = '\0';
		}
		prlen = snprintf(p, tbuf_left, "%s ", data->log_hostname);
		DEC();

		if (data->log_tag == NULL)
			data->log_tag = getprogname();
		if (data->log_pid == -1)
			data->log_pid = getpid();

		/*
		 * When sending remote we MUST follow RFC3164 sec 4.1.3,
		 * otherwise we "cheat" and allow max lenght hostname,
		 * for either log file or local syslogd -- it is up to
		 * the local syslogd then to fulfill RFC req. on output
		 */
		if (data->log_host) {
			strlcpy(tmp, data->log_tag, sizeof(tbuf));
			tag = tmp;
		}

		if (data->log_stat & LOG_PID)
			prlen = snprintf(p, tbuf_left, "%s[%d]: ", tag, data->log_pid);
		else
			prlen = snprintf(p, tbuf_left, "%s: ", tag);

		if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
			iov[iovcnt].iov_base = p;
			iov[iovcnt].iov_len = prlen;
			iovcnt++;
		}
		prlen--; /* drop extra space for regular log messages */
		DEC();
		goto output;
	}

	if (!(data->log_stat & LOG_NLOG)) {
		prlen = snprintf(p, tbuf_left, "<%d>1 ", pri);
		DEC();
	} else
		prlen = 0;

	{
		prlen = strftime(p, tbuf_left, "%FT%T", &tmnow);
		DEC();
		prlen = snprintf(p, tbuf_left, ".%06ld", (long)tv.tv_usec);
		DEC();
		prlen = strftime(p, tbuf_left-1, "%z", &tmnow);
		/* strftime gives eg. "+0200", but we need "+02:00" */
		if (prlen == 5) {
			p[prlen+1] = p[prlen];
			p[prlen]   = p[prlen-1];
			p[prlen-1] = p[prlen-2];
			p[prlen-2] = ':';
			prlen += 1;
		}

		if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
			strftime(dbuf, sizeof(dbuf), "%b %d %Y %T ", &tmnow);
			iov[iovcnt].iov_base = dbuf;
			iov[iovcnt].iov_len = strlen(dbuf);
			iovcnt++;
		}
	}

	if (data == &sdata)
		mutex_lock(&syslog_mutex);

	if (data->log_hostname[0] == '\0' && gethostname(data->log_hostname,
	    sizeof(data->log_hostname)) == -1) {
		/* can this really happen? */
		data->log_hostname[0] = '-';
		data->log_hostname[1] = '\0';
	}

	DEC();
	prlen = snprintf(p, tbuf_left, " %s ", data->log_hostname);

	if (data->log_tag == NULL)
		data->log_tag = getprogname();

	DEC();
	prlen = snprintf(p, tbuf_left, "%s ",
	    data->log_tag ? data->log_tag : "-");

	if (data == &sdata)
		mutex_unlock(&syslog_mutex);

	if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
		iov[iovcnt].iov_base = p;
		iov[iovcnt].iov_len = prlen - 1;
		iovcnt++;
	}
	DEC();

	if (data->log_stat & LOG_PID) {
		if (data->log_pid == -1)
			data->log_pid = getpid();
		prlen = snprintf(p, tbuf_left, "%d ", data->log_pid);
		if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
			iov[iovcnt].iov_base = __UNCONST("[");
			iov[iovcnt].iov_len = 1;
			iovcnt++;
			iov[iovcnt].iov_base = p;
			iov[iovcnt].iov_len = prlen - 1;
			iovcnt++;
			iov[iovcnt].iov_base = __UNCONST(BRCOSP);
			iov[iovcnt].iov_len = 3;
			iovcnt++;
		}
	} else {
		prlen = snprintf(p, tbuf_left, "- ");
		if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
			iov[iovcnt].iov_base = __UNCONST(BRCOSP + 1);
			iov[iovcnt].iov_len = 2;
			iovcnt++;
		}
	}
	DEC();

	/*
	 * concat the format strings, then use one vsnprintf()
	 */
	if (msgid != NULL && *msgid != '\0') {
		strlcat(fmt_cat, msgid, FMT_LEN);
		strlcat(fmt_cat, " ", FMT_LEN);
	} else
		strlcat(fmt_cat, "- ", FMT_LEN);

	if (sdfmt != NULL && *sdfmt != '\0') {
		strlcat(fmt_cat, sdfmt, FMT_LEN);
	} else
		strlcat(fmt_cat, "-", FMT_LEN);

output:
	if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG))
		msgsdlen = strlen(fmt_cat) + 1;
	else
		msgsdlen = 0;	/* XXX: GCC */

	if (msgfmt != NULL && *msgfmt != '\0') {
		strlcat(fmt_cat, " ", FMT_LEN);
		strlcat(fmt_cat, msgfmt, FMT_LEN);
	}

	/*
	 * We wouldn't need this mess if printf handled %m, or if
	 * strerror() had been invented before syslog().
	 */
	for (t = fmt_cpy, fmt_left = FMT_LEN; (ch = *fmt) != '\0'; ++fmt) {
		if (ch == '%' && fmt[1] == 'm') {
			const char *s;

			if ((s = strerror(saved_errno)) == NULL)
				prlen = snprintf(t, fmt_left, "Error %d",
				    saved_errno);
			else
				prlen = strlcpy(t, s, fmt_left);
			if (prlen >= fmt_left)
				prlen = fmt_left - 1;
			t += prlen;
			fmt++;
			fmt_left -= prlen;
		} else if (ch == '%' && fmt[1] == '%' && fmt_left > 2) {
			*t++ = '%';
			*t++ = '%';
			fmt++;
			fmt_left -= 2;
		} else {
			if (fmt_left > 1) {
				*t++ = ch;
				fmt_left--;
			}
		}
	}
	*t = '\0';

	prlen = vsnprintf(p, tbuf_left, fmt_cpy, ap);
	if (data->log_stat & (LOG_PERROR|LOG_CONS|LOG_NLOG)) {
		iov[iovcnt].iov_base = p + msgsdlen;
		iov[iovcnt].iov_len = prlen - msgsdlen;
		iovcnt++;
	}

	DEC();
	cnt = p - tbuf;

	/* Output to stderr if requested, PTRIM logs only message. */
	if (data->log_stat & LOG_PERROR) {
		struct iovec *piov;
		int piovcnt;

		iov[iovcnt].iov_base = __UNCONST(CRLF + 1);
		iov[iovcnt].iov_len = 1;
		if (data->log_stat & LOG_PTRIM) {
			piov = &iov[iovcnt - 1];
			piovcnt = 2;
		} else {
			piov = iov;
			piovcnt = iovcnt + 1;
		}
		(void)writev(STDERR_FILENO, piov, piovcnt + 1);
	}

	/* Don't write to system log, instead use fd in log_file */
	if (data->log_stat & LOG_NLOG) {
		iov[iovcnt].iov_base = __UNCONST(CRLF + 1);
		iov[iovcnt].iov_len = 1;
		(void)writev(data->log_file, iov, iovcnt + 1);
		goto done;
	}

	/* Get connected, output the message to the local logger. */
	if (data == &sdata)
		mutex_lock(&syslog_mutex);
	opened = !data->log_opened;
	if (opened)
		openlog_unlocked_r(data->log_tag, data->log_stat, 0, data);
	connectlog_r(data);

	/* Log to stdout, usually for debugging syslogp() API */
	if (data->log_stat & LOG_STDOUT) {
		strlcat(tbuf, "\n", sizeof(tbuf));
		write(data->log_file, tbuf, strlen(tbuf));
		goto done;
	}

	if (data->log_host) {
		sa  = data->log_host;
#ifdef HAVE_SA_LEN
		len = sa->sa_len;
#else
		len = sa_len(sa);
#endif
	}

	/*
	 * If the send() fails, there are two likely scenarios:
	 *  1) syslogd was restarted
	 *  2) /dev/log is out of socket buffer space
	 * We attempt to reconnect to /dev/log to take care of
	 * case #1 and keep send()ing data to cover case #2
	 * to give syslogd a chance to empty its socket buffer.
	 */
	for (tries = 0; tries < MAXTRIES; tries++) {
		if (sendto(data->log_file, tbuf, cnt, 0, sa, len) != -1)
			break;
		if (errno != ENOBUFS) {
			disconnectlog_r(data);
			connectlog_r(data);
		} else
			(void)usleep(1);
	}

	/*
	 * Output the message to the console; try not to block
	 * as a blocking console should not stop other processes.
	 * Make sure the error reported is the one from the syslogd failure.
	 */
	if (tries == MAXTRIES && (data->log_stat & LOG_CONS) &&
	    (fd = open(_PATH_CONSOLE,
		O_WRONLY | O_NONBLOCK | O_CLOEXEC, 0)) >= 0) {
		iov[iovcnt].iov_base = __UNCONST(CRLF);
		iov[iovcnt].iov_len = 2;
		(void)writev(fd, iov, iovcnt + 1);
		(void)close(fd);
	}

done:
	if (data == &sdata)
		mutex_unlock(&syslog_mutex);

	if (data != &sdata && opened) {
		/* preserve log tag */
		const char *ident = data->log_tag;
		closelog_r(data);
		data->log_tag = ident;
	}
}

static void
disconnectlog_r(struct syslog_data *data)
{
	/*
	 * If the user closed the FD and opened another in the same slot,
	 * that's their problem.  They should close it before calling on
	 * system services.
	 */
	if (data->log_file != -1) {
		(void)close(data->log_file);
		data->log_file = -1;
	}
	data->log_connected = 0;		/* retry connect */
}

static void
connectlog_r(struct syslog_data *data)
{
	struct sockaddr *sa = data->log_host;
	static struct sockaddr_un sun = {
		.sun_family = AF_LOCAL,
#ifdef HAVE_SA_LEN
		.sun_len = sizeof(sun),
#endif
		.sun_path = _PATH_LOG,
	};
	socklen_t len;
	int family;
	char *path;

	if (sa) {
		family = sa->sa_family;
#ifdef HAVE_SA_LEN
		len = sa->sa_len;
#else
		len = sa_len(sa);
#endif
	} else {
		sa  = (struct sockaddr *)&sun;
		family = AF_UNIX;
#ifdef HAVE_SA_LEN
		len = sa->sa_len;
#else
		len = sizeof(sun);
#endif

		path = getenv("SYSLOG_UNIX_PATH");
		if (!data->log_sockpath && path)
			data->log_sockpath = path;

		if (data->log_sockpath && !access(data->log_sockpath, W_OK))
			strlcpy(sun.sun_path, data->log_sockpath, sizeof(sun.sun_path));
	}

	if (data->log_file == -1 || fcntl(data->log_file, F_GETFL, 0) == -1) {
		data->log_file = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (data->log_file == -1)
			return;
		data->log_connected = 0;
	}

	if (!data->log_connected) {
		if (!is_socket(data->log_file)) {
			data->log_connected = 1;
			return;
		}

		if (connect(data->log_file, sa, len) == -1) {
			(void)close(data->log_file);
			data->log_file = -1;
		} else
			data->log_connected = 1;
	}
}

static void
openlog_unlocked_r(const char *ident, int logstat, int logfac,
    struct syslog_data *data)
{
	if (ident != NULL)
		data->log_tag = ident;
	data->log_stat = logstat;
	if (logfac != 0 && (logfac &~ LOG_FACMASK) == 0)
		data->log_fac = logfac;

	if (data->log_stat & LOG_NDELAY) {	/* open immediately */
		connectlog_r(data);
		if (data->log_connected)
			data->log_opened = 1;
	} else
		data->log_opened = 1;
}

void
openlog_r(const char *ident, int logstat, int logfac, struct syslog_data *data)
{
	if (data == &sdata)
		mutex_lock(&syslog_mutex);
	openlog_unlocked_r(ident, logstat, logfac, data);
	if (data == &sdata)
		mutex_unlock(&syslog_mutex);
}

void
closelog_r(struct syslog_data *data)
{
	if (data == &sdata)
		mutex_lock(&syslog_mutex);
	(void)close(data->log_file);
	data->log_file = -1;
	data->log_connected = 0;
	data->log_tag = NULL;
	if (data == &sdata)
		mutex_unlock(&syslog_mutex);
}

int
setlogmask_r(int pmask, struct syslog_data *data)
{
	int omask;

	omask = data->log_mask;
	if (pmask != 0)
		data->log_mask = pmask;
	return omask;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
