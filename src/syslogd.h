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

#ifndef SYSKLOGD_SYSLOGD_H_
#define SYSKLOGD_SYSLOGD_H_

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>		/* struct addrinfo */
#include <string.h>
#ifdef __linux__
#include <sys/klog.h>
#endif
#include <sys/param.h>		/* MAXHOSTNAMELEN */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>		/* struct sockaddr_un */
#include "queue.h"
#include "syslog.h"

#ifndef MAXLINE
#define MAXLINE        2048            /* maximum line length */
#endif
#define MAXSVLINE      MAXLINE         /* maximum saved line length */
#define DEFUPRI        (LOG_USER | LOG_NOTICE)
#define DEFSPRI        (LOG_KERN | LOG_CRIT)
#define TIMERINTVL     30              /* interval for checking flush/nslookup */
#define RCVBUF_MINSIZE (80 * MAXLINE)  /* minimum size of dgram rcv buffer */

/*
 * Linux uses EIO instead of EBADFD (mrn 12 May 96)
 */
#ifdef __linux__
#define EHANGUP EIO
#else
#define EHANGUP EBADFD
#endif

#ifndef UTMP_FILE
#ifdef UTMP_FILENAME
#define UTMP_FILE UTMP_FILENAME
#else
#ifdef _PATH_UTMP
#define UTMP_FILE _PATH_UTMP
#else
#define UTMP_FILE "/etc/utmp"
#endif
#endif
#endif

#ifndef _PATH_LOGCONF
#define _PATH_LOGCONF  SYSCONFDIR "/syslog.conf"
#endif

#ifndef _PATH_LOGPID
#define _PATH_LOGPID RUNSTATEDIR "/syslogd.pid"
#endif

#ifndef _PATH_CACHE
#define _PATH_CACHE  RUNSTATEDIR "/syslogd.cache"
#endif

#ifndef _PATH_DEV
#define _PATH_DEV      "/dev/"
#endif

#ifndef _PATH_CONSOLE
#define _PATH_CONSOLE  "/dev/console"
#endif

#ifndef _PATH_TTY
#define _PATH_TTY      "/dev/tty"
#endif

#ifndef _PATH_LOG
#define _PATH_LOG      "/dev/log"
#endif

#ifndef _PATH_KLOG
#define _PATH_KLOG	"/proc/kmsg"
#endif

#ifdef UT_NAMESIZE
#define UNAMESZ        UT_NAMESIZE /* length of a login name */
#else
#define UNAMESZ        8      /* length of a login name */
#endif
#define MAXUNAMES      20     /* maximum number of user names */
#define MAXFNAME       200    /* max file pathname length */

#ifndef INET_SUSPEND_TIME
#define INET_SUSPEND_TIME 180 /* equal to 3 minutes */
#endif

#define LIST_DELIMITER    ':' /* delimiter between two hosts */

#define	AI_SECURE	0x8000	/* Tell socket_create() to not bind() */

#define O_CREATE        O_WRONLY | O_APPEND | O_CREAT

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

/* Stringification macros, see signal_init() for an example */
#define xstr(s) str(s)
#define str(s) #s

/* Helper internal log macros */
#define ERR(fmt,  args...)	flog(LOG_SYSLOG | LOG_ERR, fmt ": %s", ##args, strerror(errno))
#define ERRX(fmt, args...)	flog(LOG_SYSLOG | LOG_ERR, fmt, ##args)
#define WARN(fmt, args...)	flog(LOG_SYSLOG | LOG_WARN, fmt, ##args)
#define NOTE(fmt, args...)	flog(LOG_SYSLOG | LOG_NOTICE, fmt, ##args)
#define INFO(fmt, args...)	flog(LOG_SYSLOG | LOG_INFO, fmt, ##args)

/*
 * Help macros to convert between sockaddr types
 */
#define	sstosa(ss)	((struct sockaddr *)(ss))
#define	sstosin(ss)	((struct sockaddr_in *)(void *)(ss))
#define	satosin(sa)	((struct sockaddr_in *)(void *)(sa))
#define	sstosin6(ss)	((struct sockaddr_in6 *)(void *)(ss))
#define	satosin6(sa)	((struct sockaddr_in6 *)(void *)(sa))
#ifndef s6_addr32
#define	s6_addr32	__u6_addr.__u6_addr32
#endif
#define	IN6_ARE_MASKED_ADDR_EQUAL(d, a, m)	(	\
	(((d)->s6_addr32[0] ^ (a)->s6_addr32[0]) & (m)->s6_addr32[0]) == 0 && \
	(((d)->s6_addr32[1] ^ (a)->s6_addr32[1]) & (m)->s6_addr32[1]) == 0 && \
	(((d)->s6_addr32[2] ^ (a)->s6_addr32[2]) & (m)->s6_addr32[2]) == 0 && \
	(((d)->s6_addr32[3] ^ (a)->s6_addr32[3]) & (m)->s6_addr32[3]) == 0 )

/*
 * klogctl(2) commands on Linux to control kernel logging to console.
 */
#define SYSLOG_ACTION_CONSOLE_OFF 6
#define SYSLOG_ACTION_CONSOLE_ON  7

#ifdef __linux__
#define kern_console_off() klogctl(SYSLOG_ACTION_CONSOLE_OFF, NULL, 0)
#define kern_console_on()  klogctl(SYSLOG_ACTION_CONSOLE_ON, NULL, 0)
#else
#define kern_console_off() do { } while (0)
#define kern_console_on()  do { } while (0)
#endif

/*
 * Flags to logmsg().
 */
#define IGN_CONS  0x001  /* don't print on console */
#define SYNC_FILE 0x002  /* do fsync on file after printing */
#define ADDDATE   0x004  /* add a date to the message */
#define MARK      0x008  /* this message is a mark */
#define RFC3164   0x010  /* format log message according to RFC 3164 */
#define RFC5424   0x020  /* format log message according to RFC 5424 */
#define SUSP_RETR 0x040  /* suspend/forw_unkn, retrying nslookup */

/* Syslog timestamp formats. */
#define	BSDFMT_DATELEN	0
#define	BSDFMT_DATEFMT	NULL

#define	RFC3164_DATELEN	15
#define	RFC3164_DATEFMT	"%b %e %H:%M:%S"

#define	RFC5424_DATELEN	32
#define	RFC5424_DATEFMT	"%FT%T.______%z"

/*
 * Helper macros for "message repeated" messages
 */
#define MAXREPEAT ((sizeof(repeatinterval) / sizeof(repeatinterval[0])) - 1)
#define REPEATTIME(f) ((f)->f_time + repeatinterval[(f)->f_repeatcount])
#define BACKOFF(f)                                      \
		if (++(f)->f_repeatcount > MAXREPEAT)   \
			(f)->f_repeatcount = MAXREPEAT;

/* values for f_type */
#define F_UNUSED          0   /* unused entry */
#define F_FILE            1   /* regular file */
#define F_TTY             2   /* terminal */
#define F_CONSOLE         3   /* console terminal */
#define F_FORW            4   /* remote machine */
#define F_USERS           5   /* list of users */
#define F_WALL            6   /* everyone logged on */
#define F_FORW_SUSP       7   /* suspended host forwarding */
#define F_FORW_UNKN       8   /* unknown host forwarding */
#define F_PIPE            9   /* named pipe */

/*
 * Struct to hold records of peers and sockets
 */
struct peer {
	SIMPLEQ_ENTRY(peer)	pe_link;
	const char	*pe_name;
	const char	*pe_serv;
	mode_t		 pe_mode;
	int		 pe_sock[16];
	size_t		 pe_socknum;
};

/*
 * Struct to hold records of network addresses that are allowed to log
 * to us.
 */
struct allowedpeer {
	SIMPLEQ_ENTRY(allowedpeer)	next;
	int isnumeric;
	u_short port;
	union {
		struct {
			struct sockaddr_storage addr;
			struct sockaddr_storage mask;
		} numeric;
		char *name;
	} u;
#define a_addr u.numeric.addr
#define a_mask u.numeric.mask
#define a_name u.name
};

/* Timestamps of log entries. */
struct logtime {
	struct tm       tm;
	suseconds_t     usec;
};

/* message buffer container used for processing, formatting, and queueing */
struct buf_msg {
	int	 	 pri;
	char		 pribuf[8];
	int	 	 flags;
	struct logtime	 timestamp;
	char		 timebuf[33];
	char		*recvhost;
	char		*hostname;
	char		*app_name;
	char		*proc_id;
	char		*msgid;
	char		*sd;	       /* structured data */
	char		*msg;	       /* message content */
};

/*
 * This structure represents the files that will have log
 * copies printed.
 * We require f_file to be valid if f_type is F_FILE, F_CONSOLE, F_TTY
 * or if f_type is F_PIPE and f_pid > 0.
 */
struct filed {
	SIMPLEQ_ENTRY(filed) f_link;

	short	 f_type;                       /* entry type, see below */
	short	 f_file;                       /* file descriptor */
	time_t	 f_time;                       /* time this was last written */
	char	*f_host;                       /* host from which to recd. */
	u_char	 f_pmask[LOG_NFACILITIES + 1]; /* priority mask */
	union {
		char f_uname[MAXUNAMES][UNAMESZ + 1];
		struct {
			char f_hname[MAXHOSTNAMELEN + 1];
			char f_serv[20];
			struct addrinfo *f_addr;
		} f_forw; /* forwarding address */
		char f_fname[MAXFNAME];
	} f_un;
	char	 f_prevline[MAXSVLINE];        /* last message logged */
	struct logtime f_lasttime;             /* time of last occurrence */
	char	 f_prevhost[MAXHOSTNAMELEN + 1]; /* host from which recd. */
	int	 f_prevpri;                    /* pri of f_prevline */
	size_t	 f_prevlen;                    /* length of f_prevline */
	size_t	 f_prevcount;                  /* repetition cnt of prevline */
	size_t	 f_repeatcount;                /* number of "repeated" msgs */
	int	 f_flags;                      /* store some additional flags */
	int	 f_rotatecount;
	int	 f_rotatesz;
};

/*
 * Log rotation notifiers
 */
struct notifier {
	SIMPLEQ_ENTRY(notifier)	 n_link;
	char			*n_program;
};

void flog(int pri, char *fmt, ...);

#endif /* SYSKLOGD_SYSLOGD_H_ */
