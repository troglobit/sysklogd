/*	$NetBSD: syslog.h,v 1.34.8.3 2017/12/03 11:39:21 jdolecek Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *
 *	@(#)syslog.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _SYS_SYSLOG_H_ /* From NetBSD, for co-existance with C-library header */
#define _SYS_SYSLOG_H_

#include <stdarg.h>

/*
 * Default on *BSD is /var/run/log, but on Linux systems with systemd
 * (journald) this is reserved and may already exist as a directory.
 * For compatibility with GLIBC syslog API, for those who opt not to
 * use this replacement API, we use the default/traditional Linux path
 * /dev/log in the sysklogd project.
 */
#ifndef __linux__
#define	_PATH_LOG	"/var/run/log"
#else
#define	_PATH_LOG	"/dev/log"
#endif

/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARN	4	/* warning conditions, alias */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

#define	LOG_PRIMASK	0x07	/* mask to extract priority part (internal) */
				/* extract priority */
#define	LOG_PRI(p)	((p) & LOG_PRIMASK)
#define	LOG_MAKEPRI(fac, pri)	((fac) | (pri))

#ifdef SYSLOG_NAMES
#define INTERNAL_INVPRI 0x00    /* Value to indicate no priority in f_pmask */
#define	INTERNAL_NOPRI	0x10	/* the "no priority" priority */
				/* mark "facility" */
#define INTERNAL_ALLPRI 0xFF   /* Value to indicate all priorities in f_pmask */
#define	INTERNAL_MARK	LOG_MAKEPRI(LOG_NFACILITIES << 3, 0)
#undef CODE
typedef struct _code {
	const char	*c_name;
	int	c_val;
} CODE;

CODE prioritynames[] = {
	{ "alert",	LOG_ALERT },
	{ "crit",	LOG_CRIT },
	{ "debug",	LOG_DEBUG },
	{ "emerg",	LOG_EMERG },
	{ "err",	LOG_ERR },
	{ "error",	LOG_ERR },		/* DEPRECATED */
	{ "info",	LOG_INFO },
	{ "none",	INTERNAL_NOPRI },	/* INTERNAL */
	{ "notice",	LOG_NOTICE },
	{ "panic",	LOG_EMERG },		/* DEPRECATED */
	{ "warn",	LOG_WARNING },		/* DEPRECATED */
	{ "warning",	LOG_WARNING },
	{ "*",		INTERNAL_ALLPRI },	/* INTERNAL */
	{ NULL,		-1 }
};
#endif /* SYSLOG_NAMES */

/* facility codes */
#define	LOG_KERN	(0<<3)	/* kernel messages */
#define	LOG_USER	(1<<3)	/* random user-level messages */
#define	LOG_MAIL	(2<<3)	/* mail system */
#define	LOG_DAEMON	(3<<3)	/* system daemons */
#define	LOG_AUTH	(4<<3)	/* security/authorization messages */
#define	LOG_SYSLOG	(5<<3)	/* messages generated internally by syslogd */
#define	LOG_LPR		(6<<3)	/* line printer subsystem */
#define	LOG_NEWS	(7<<3)	/* network news subsystem */
#define	LOG_UUCP	(8<<3)	/* UUCP subsystem */
#define	LOG_CRON	(9<<3)	/* clock daemon */
#define	LOG_AUTHPRIV	(10<<3)	/* security/authorization messages (private) */
#define	LOG_FTP		(11<<3)	/* ftp daemon */
#define	LOG_NTP		(12<<3)	/* NTP subsystem */
#define	LOG_SECURITY	(13<<3)	/* Log audit, for audit trails */
#define	LOG_CONSOLE	(14<<3)	/* Log alert */
#define	LOG_CRON_SOL	(15<<3)	/* clock daemon (Solaris) */
#define	LOG_LOCAL0	(16<<3)	/* reserved for local use */
#define	LOG_LOCAL1	(17<<3)	/* reserved for local use */
#define	LOG_LOCAL2	(18<<3)	/* reserved for local use */
#define	LOG_LOCAL3	(19<<3)	/* reserved for local use */
#define	LOG_LOCAL4	(20<<3)	/* reserved for local use */
#define	LOG_LOCAL5	(21<<3)	/* reserved for local use */
#define	LOG_LOCAL6	(22<<3)	/* reserved for local use */
#define	LOG_LOCAL7	(23<<3)	/* reserved for local use */

#define	LOG_NFACILITIES	24	/* current number of facilities */
#define	LOG_FACMASK	0x03f8	/* mask to extract facility part */
				/* facility of pri */
#define	LOG_FAC(p)	(((p) & LOG_FACMASK) >> 3)

#ifdef SYSLOG_NAMES
CODE facilitynames[] = {
	{ "auth",	LOG_AUTH },
	{ "authpriv",	LOG_AUTHPRIV },
	{ "console",	LOG_CONSOLE },
	{ "cron",	LOG_CRON },
	{ "cron_sol",	LOG_CRON_SOL },		/* Solaris cron */
	{ "daemon",	LOG_DAEMON },
	{ "ftp",	LOG_FTP },
	{ "kern",	LOG_KERN },
	{ "lpr",	LOG_LPR },
	{ "mail",	LOG_MAIL },
	{ "mark",	INTERNAL_MARK },	/* INTERNAL */
	{ "news",	LOG_NEWS },
	{ "ntp",	LOG_NTP },
	{ "security",	LOG_SECURITY },
	{ "syslog",	LOG_SYSLOG },
	{ "user",	LOG_USER },
	{ "uucp",	LOG_UUCP },
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
	{ NULL,		-1 }
};
#endif /* SYSLOG_NAMES */

#ifdef __KERNEL__
#define	LOG_PRINTF	-1	/* pseudo-priority to indicate use of printf */
#endif

/*
 * arguments to setlogmask.
 */
#define	LOG_MASK(pri)	(1 << (pri))		/* mask for one priority */
#define	LOG_UPTO(pri)	((1 << ((pri)+1)) - 1)	/* all priorities through pri */

/*
 * Option flags for openlog.
 *
 * LOG_ODELAY no longer does anything.
 * LOG_NDELAY is the inverse of what it used to be.
 */
#define	LOG_PID		0x001	/* log the pid with each message */
#define	LOG_CONS	0x002	/* log on the console if errors in sending */
#define	LOG_ODELAY	0x004	/* delay open until first syslog() (default) */
#define	LOG_NDELAY	0x008	/* don't delay open */
#define	LOG_NOWAIT	0x010	/* don't wait for console forks: DEPRECATED */
#define	LOG_PERROR	0x020	/* log to stderr as well */
#define	LOG_PTRIM	0x040	/* trim anything syslog addded when writing to stderr */
#define	LOG_NLOG	0x080	/* don't write to the system log */
#define	LOG_STDOUT	0x100	/* like nlog, for debugging syslogp() API */
#define	LOG_RFC3164     0x200	/* Log to remote/ipc socket in old BSD format */

#ifndef __KERNEL__

/* Used by reentrant functions */

struct syslog_data {
	int	log_version;
	int	log_file;
	int	log_connected;
	int	log_opened;
	int	log_stat;
	const char	*log_tag;
	const char	*log_sockpath;	/* Path to socket */
	char	log_hostname[256];	/* MAXHOSTNAMELEN */
	int	log_fac;
	int	log_mask;
	void	*log_host;		/* struct sockaddr* */
	int     log_pid;
};

#define SYSLOG_DATA_INIT { \
    .log_version = 1, \
    .log_file = -1, \
    .log_connected = 0, \
    .log_opened = 0, \
    .log_stat = 0, \
    .log_tag  = 0, \
    .log_sockpath = NULL, \
    .log_hostname = { '\0' }, \
    .log_fac = LOG_USER, \
    .log_mask = 0xff, \
    .log_host = NULL, \
    .log_pid = -1, \
}

#ifdef __cplusplus
extern "C" {
#endif
void	openlog    (const char *, int, int);
void	closelog   (void);

int	setlogmask (int);

void	syslog     (int, const char *, ...);
void	vsyslog    (int, const char *, va_list);

void	syslogp    (int, const char *, const char *, const char *, ...);
void	vsyslogp   (int, const char *, const char *, const char *, va_list);

void	openlog_r  (const char *, int, int, struct syslog_data *);
void	closelog_r (struct syslog_data *);

int	setlogmask_r (int, struct syslog_data *);

void	syslog_r   (int, struct syslog_data *, const char *, ...);
void	vsyslog_r  (int, struct syslog_data *, const char *, va_list);

void	syslogp_r  (int, struct syslog_data *, const char *, const char *,
		    const char *, ...);
void	vsyslogp_r (int, struct syslog_data *, const char *, const char *,
		    const char *, va_list);
#ifdef __cplusplus
}
#endif

#else /* !__KERNEL__ */

void	logpri(int);
void	log(int, const char *, ...);
void	vlog(int, const char *, va_list);
void	addlog(const char *, ...);
void	logwakeup(void);

#endif /* !__KERNEL__ */

#endif /* !_SYS_SYSLOG_H_ */
