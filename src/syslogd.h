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

#include "queue.h"
#include "syslog.h"

#ifdef UT_NAMESIZE
#define UNAMESZ        UT_NAMESIZE /* length of a login name */
#else
#define UNAMESZ        8      /* length of a login name */
#endif
#define MAXUNAMES      20     /* maximum number of user names */
#define MAXFNAME       200    /* max file pathname length */

#define INTERNAL_NOPRI 0x10   /* the "no priority" priority */
#define TABLE_NOPRI    0      /* Value to indicate no priority in f_pmask */
#define TABLE_ALLPRI   0xFF   /* Value to indicate all priorities in f_pmask */
#define LOG_MARK       LOG_MAKEPRI(LOG_NFACILITIES, 0) /* mark "facility" */

#define MAX_PRI        191    /* Maximum Priority per RFC 3164 */

/* Traditional syslog timestamp format. */
#define	RFC3164_DATELEN	15
#define	RFC3164_DATEFMT	"%b %e %H:%M:%S"

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

/* Timestamps of log entries. */
struct logtime {
	struct tm       tm;
	suseconds_t     usec;
};

/* message buffer container used for processing, formatting, and queueing */
struct buf_msg {
	int	 	 pri;
	char		 pribuf[7];
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
			struct addrinfo *f_addr;
		} f_forw; /* forwarding address */
		char f_fname[MAXFNAME];
	} f_un;
	char	 f_prevline[MAXSVLINE];        /* last message logged */
	struct logtime f_lasttime;             /* time of last occurrence */
	char	 f_prevhost[MAXHOSTNAMELEN + 1]; /* host from which recd. */
	int	 f_prevpri;                    /* pri of f_prevline */
	size_t	 f_prevlen;                    /* length of f_prevline */
	int	 f_prevcount;                  /* repetition cnt of prevline */
	size_t	 f_repeatcount;                /* number of "repeated" msgs */
	int	 f_flags;                      /* store some additional flags */
	int	 f_rotatecount;
	int	 f_rotatesz;
};

#endif /* SYSKLOGD_SYSLOGD_H_ */
