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

#ifndef lint
static const char copyright[] __attribute__((unused)) =
	"@(#) Copyright (c) 1983, 1988, 1993\n\
		The Regents of the University of California.  All rights reserved.\n";
static char sccsid[] __attribute__((unused)) =
	"@(#)syslogd.c	5.27 (Berkeley) 10/10/88";
#endif

/*
 *  syslogd -- log system messages
 *
 * This program implements a system log. It takes a series of lines.
 * Each line may have a priority, signified as "<n>" as
 * the first characters of the line.  If this is
 * not present, a default priority is used.
 *
 * To kill syslogd, send a signal 15 (terminate).  A signal 1 (hup) will
 * cause it to reread its configuration file.
 *
 */

#define MAXLINE        1024            /* maximum line length */
#define MAXSVLINE      240             /* maximum saved line length */
#define DEFUPRI        (LOG_USER | LOG_NOTICE)
#define DEFSPRI        (LOG_KERN | LOG_CRIT)
#define TIMERINTVL     30              /* interval for checking flush, mark */
#define RCVBUF_MINSIZE (80 * 1024)     /* minimum size of dgram rcv buffer */

#include <ctype.h>
#include <getopt.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#define SYSLOG_NAMES
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <syscall.h>
#ifndef TESTING
#include "pidfile.h"
#endif
#include "config.h"
#include <paths.h>
#include "syslog.h"
#include "compat.h"

/*
 * Linux uses EIO instead of EBADFD (mrn 12 May 96)
 */
#ifdef linux
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
#define _PATH_LOGCONF  "/etc/syslog.conf"
#endif

#if defined(SYSLOGD_PIDNAME)
#undef _PATH_LOGPID
#define _PATH_LOGPID _PATH_VARRUN SYSLOGD_PIDNAME
#else
#ifndef _PATH_LOGPID
#define _PATH_LOGPID _PATH_VARRUN "syslogd.pid"
#endif
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

char *ConfFile = _PATH_LOGCONF;
char *PidFile  = _PATH_LOGPID;
char  ctty[]  = _PATH_CONSOLE;

char **parts;

static int debugging_on = 0;
static int nlogs = -1;
static int restart = 0;

#define MAXFUNIX 20

int   nfunix = 1;
char *funixn[MAXFUNIX] = { _PATH_LOG };
int   funix[MAXFUNIX] = {
        -1,
};

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

/*
 * Flags to logmsg().
 */

#define IGN_CONS  0x001  /* don't print on console */
#define SYNC_FILE 0x002  /* do fsync on file after printing */
#define ADDDATE   0x004  /* add a date to the message */
#define MARK      0x008  /* this message is a mark */
#define RFC5424   0x010  /* format log message according to RFC 5424 */

/* Timestamps of log entries. */
struct logtime {
	struct tm       tm;
	suseconds_t     usec;
};


/*
 * This table contains plain text for h_errno errors used by the
 * net subsystem.
 */
const char *sys_h_errlist[] = {
	"No problem",                                              /* NETDB_SUCCESS */
	"Authoritative answer: host not found",                    /* HOST_NOT_FOUND */
	"Non-authoritative answer: host not found, or serverfail", /* TRY_AGAIN */
	"Non recoverable errors",                                  /* NO_RECOVERY */
	"Valid name, no data record of requested type",            /* NO_DATA */
	"no address, look for MX record"                           /* NO_ADDRESS */
};

/*
 * This structure represents the files that will have log
 * copies printed.
 */

struct filed {
	struct filed *f_next;                /* next in linked list */

	short  f_type;                       /* entry type, see below */
	short  f_file;                       /* file descriptor */
	time_t f_time;                       /* time this was last written */
	char * f_host;                       /* host from which to recd. */
	u_char f_pmask[LOG_NFACILITIES + 1]; /* priority mask */
	union {
		char f_uname[MAXUNAMES][UNAMESZ + 1];
		struct {
			char             f_hname[MAXHOSTNAMELEN + 1];
			struct addrinfo *f_addr;
		} f_forw; /* forwarding address */
		char f_fname[MAXFNAME];
	} f_un;
	char   f_prevline[MAXSVLINE];          /* last message logged */
	char   f_lasttime[16];                 /* time of last occurrence */
	char   f_prevhost[MAXHOSTNAMELEN + 1]; /* host from which recd. */
	int    f_prevpri;                      /* pri of f_prevline */
	int    f_prevlen;                      /* length of f_prevline */
	int    f_prevcount;                    /* repetition cnt of prevline */
	size_t f_repeatcount;                  /* number of "repeated" msgs */
	int    f_flags;                        /* store some additional flags */
	int    f_rotatecount;
	int    f_rotatesz;
};

/*
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
int repeatinterval[] = { 30, 60 }; /* # of secs before flush */
#define MAXREPEAT ((sizeof(repeatinterval) / sizeof(repeatinterval[0])) - 1)
#define REPEATTIME(f) ((f)->f_time + repeatinterval[(f)->f_repeatcount])
#define BACKOFF(f)                                      \
	{                                               \
		if (++(f)->f_repeatcount > MAXREPEAT)   \
			(f)->f_repeatcount = MAXREPEAT; \
	}
#ifndef INET_SUSPEND_TIME
#define INET_SUSPEND_TIME 180 /* equal to 3 minutes */
#endif
#define INET_RETRY_MAX    10  /* maximum of retries for getaddrinfo() */

#define LIST_DELIMITER    ':' /* delimiter between two hosts */

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
char *TypeNames[] = {
	"UNUSED",        "FILE",  "TTY",  "CONSOLE",
	"FORW",          "USERS", "WALL", "FORW(SUSPENDED)",
	"FORW(UNKNOWN)", "PIPE"
};

struct filed *Files = NULL;
struct filed consfile;

struct code {
	char *c_name;
	int   c_val;
};

struct code PriNames[] = {
	{ "alert",    LOG_ALERT      },
	{ "crit",     LOG_CRIT       },
	{ "debug",    LOG_DEBUG      },
	{ "emerg",    LOG_EMERG      },
	{ "err",      LOG_ERR        },
	{ "error",    LOG_ERR        },  /* DEPRECATED */
	{ "info",     LOG_INFO       },
	{ "none",     INTERNAL_NOPRI },  /* INTERNAL */
	{ "notice",   LOG_NOTICE     },
	{ "panic",    LOG_EMERG      },  /* DEPRECATED */
	{ "warn",     LOG_WARNING    }, /* DEPRECATED */
	{ "warning",  LOG_WARNING    },
	{ "*",        TABLE_ALLPRI   },
	{ NULL,       -1             }
};

struct code FacNames[] = {
	{ "auth",     LOG_AUTH       },
	{ "authpriv", LOG_AUTHPRIV   },
	{ "cron",     LOG_CRON       },
	{ "daemon",   LOG_DAEMON     },
	{ "kern",     LOG_KERN       },
	{ "lpr",      LOG_LPR        },
	{ "mail",     LOG_MAIL       },
	{ "mark",     LOG_MARK       },  /* INTERNAL */
	{ "news",     LOG_NEWS       },
	{ "security", LOG_AUTH       },  /* DEPRECATED */
	{ "syslog",   LOG_SYSLOG     },
	{ "user",     LOG_USER       },
	{ "uucp",     LOG_UUCP       },
#if defined(LOG_FTP)
	{ "ftp",      LOG_FTP        },
#endif
	{ "local0",   LOG_LOCAL0     },
	{ "local1",   LOG_LOCAL1     },
	{ "local2",   LOG_LOCAL2     },
	{ "local3",   LOG_LOCAL3     },
	{ "local4",   LOG_LOCAL4     },
	{ "local5",   LOG_LOCAL5     },
	{ "local6",   LOG_LOCAL6     },
	{ "local7",   LOG_LOCAL7     },
	{ NULL,       -1             },
};

static int	Debug;		/* debug flag */
static int	Foreground = 0;	/* don't fork - don't run in daemon mode */
char  LocalHostName[MAXHOSTNAMELEN + 1]; /* our hostname */
char *LocalDomain;                       /* our local domain name */
char *emptystring = "";
int   InetInuse = 0;          /* non-zero if INET sockets are being used */
int  *finet = NULL;           /* Internet datagram sockets */
int   Initialized = 0;        /* set when we have initialized ourselves */
int   MarkInterval = 20 * 60; /* interval between marks in seconds */
int    family = PF_UNSPEC;  /* protocol family (IPv4, IPv6 or both) */
int    send_to_all = 0;     /* send message to all IPv4/IPv6 addresses */
int    MarkSeq = 0;         /* mark sequence number */
int    LastAlarm = 0;       /* last value passed to alarm() (seconds)  */
int    DupesPending = 0;    /* Number of unflushed duplicate messages */
int    NoFork = 0;          /* don't fork - don't run in daemon mode */
int    AcceptRemote = 0;    /* receive messages that come via UDP */
char **StripDomains = NULL; /* these domains may be stripped before writing logs */
char **LocalHosts = NULL;   /* these hosts are logged with their hostname */
int    NoHops = 1;          /* Can we bounce syslog messages through an intermediate host. */
static off_t	RotateSz = 0;	/* Max file size (bytes) before rotating, disabled by default */
static int	RotateCnt = 5;	/* Max number (count) of log files to keep, set with -c <NUM> */
extern int errno;

/* Function prototypes. */
char      **crunch_list(char *list);
int         usage(int code);
void        untty(void);
void        printchopped(const char *hname, char *msg, size_t len, int fd);
void        printline(const char *hname, char *msg);
void        printsys(char *msg);
void        logmsg(int pri, char *msg, const char *from, int flags);
void        fprintlog(struct filed *f, char *from, int flags, char *msg);
void        endtty();
void        wallmsg(struct filed *f, struct iovec *iov);
void        reapchild();
const char *cvtaddr(struct sockaddr_storage *f, int len);
const char *cvthname(struct sockaddr_storage *f, int len);
void        domark();
void        debug_switch();
void        logerror(const char *type);
void        die(int sig);
#ifndef TESTING
void        doexit(int sig);
#endif
void        init();
static int  strtobytes(char *arg);
void        cfline(char *line, struct filed *f);
int         decode(char *name, struct code *codetab);
static void logit(char *, ...);
void        sighup_handler(int);
static int  create_unix_socket(const char *path);
static int *create_inet_sockets();


int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
#ifndef TESTING
	struct sockaddr_storage frominet;
	pid_t ppid = getpid();
	socklen_t len;
	ssize_t msglen;
	int fd;
#endif
	fd_set readfds;
	char line[MAXLINE + 1];
	int num_fds, maxfds;
	int i, ch;

	for (i = 1; i < MAXFUNIX; i++) {
		funixn[i] = "";
		funix[i] = -1;
	}

	while ((ch = getopt(argc, argv, "46Aa:dhf:l:m:np:R:rs:v?")) != EOF) {
		switch ((char)ch) {
		case '4':
			family = PF_INET;
			break;

		case '6':
			family = PF_INET6;
			break;

		case 'A':
			send_to_all++;
			break;

		case 'a':
			if (nfunix < MAXFUNIX)
				funixn[nfunix++] = optarg;
			else
				fprintf(stderr, "Out of descriptors, ignoring %s\n", optarg);
			break;

		case 'd': /* debug */
			Debug = 1;
			break;

		case 'f': /* configuration file */
			ConfFile = optarg;
			break;

		case 'h':
			NoHops = 0;
			break;

		case 'l':
			if (LocalHosts) {
				fprintf(stderr, "Only one -l argument allowed,"
				                "the first one is taken.\n");
				break;
			}
			LocalHosts = crunch_list(optarg);
			break;

		case 'm': /* mark interval */
			MarkInterval = atoi(optarg) * 60;
			break;

		case 'n': /* don't fork */
			Foreground = 1;
			break;

		case 'p': /* path to regular log socket */
			funixn[0] = optarg;
			break;

		case 'R':
			parse_rotation(optarg, &RotateSz, &RotateCnt);
			break;

		case 'r': /* accept remote messages */
			AcceptRemote = 1;
			break;

		case 's':
			if (StripDomains) {
				fprintf(stderr, "Only one -s argument allowed,"
				                "the first one is taken.\n");
				break;
			}
			StripDomains = crunch_list(optarg);
			break;

		case 'v':
			printf("syslogd v%s\n", VERSION);
			exit(0);

		case '?':
			usage(0);
			break;

		default:
			usage(1);
			break;
		}
	}

	if ((argc -= optind))
		usage(1);

#ifndef TESTING
	if ((!Foreground) && (!Debug)) {
		logit("Checking pidfile.\n");
		if (!check_pid(PidFile)) {
			signal(SIGTERM, doexit);
			chdir("/");

			if (fork()) {
				/*
				 * Parent process
				 */
				sleep(300);
				/*
				 * Not reached unless something major went wrong.  5
				 * minutes should be a fair amount of time to wait.
				 * Please note that this procedure is important since
				 * the father must not exit before syslogd isn't
				 * initialized or the klogd won't be able to flush its
				 * logs.  -Joey
				 */
				exit(1);
			}
			signal(SIGTERM, SIG_DFL);
			num_fds = getdtablesize();
			for (i = 0; i < num_fds; i++)
				(void)close(i);
			untty();
		} else {
			fputs("syslogd: Already running.\n", stderr);
			exit(1);
		}
	} else
#endif
	{
		debugging_on = 1;
		setlinebuf(stdout);
	}

#ifndef TESTING
	/* tuck my process id away */
	if (!Debug) {
		logit("Writing pidfile.\n");
		if (!check_pid(PidFile)) {
			if (!write_pid(PidFile)) {
				logit("Can't write pid.\n");
				if (getpid() != ppid)
					kill(ppid, SIGTERM);
				exit(1);
			}
		} else {
			logit("Pidfile (and pid) already exist.\n");
			if (getpid() != ppid)
				kill(ppid, SIGTERM);
			exit(1);
		}
	} /* if ( !Debug ) */
#endif

	consfile.f_type = F_CONSOLE;
	(void)strcpy(consfile.f_un.f_fname, ctty);

	/* Initialization is done by init() */
	(void)strcpy(LocalHostName, emptystring);
	LocalDomain = emptystring;

	(void)signal(SIGTERM, die);
	(void)signal(SIGINT, Debug ? die : SIG_IGN);
	(void)signal(SIGQUIT, Debug ? die : SIG_IGN);
	(void)signal(SIGCHLD, reapchild);
	(void)signal(SIGALRM, domark);
	(void)signal(SIGUSR1, Debug ? debug_switch : SIG_IGN);
	(void)signal(SIGXFSZ, SIG_IGN);

	LastAlarm = MarkInterval;
	alarm(LastAlarm);

	/* Create a partial message table for all file descriptors. */
	num_fds = getdtablesize();
	logit("Allocated parts table for %d file descriptors.\n", num_fds);
	if ((parts = malloc(num_fds * sizeof(char *))) == NULL) {
		logerror("Cannot allocate memory for message parts table.");
#ifndef TESTING
		if (getpid() != ppid)
			kill(ppid, SIGTERM);
#endif
		die(0);
	}
	for (i = 0; i < num_fds; ++i)
		parts[i] = NULL;

	logit("Starting.\n");
	init();
#ifndef TESTING
	if (Debug) {
		logit("Debugging disabled, SIGUSR1 to turn on debugging.\n");
		debugging_on = 0;
	}
	/*
	 * Send a signal to the parent to it can terminate.
	 */
	if (getpid() != ppid)
		kill(ppid, SIGTERM);
#endif

	/* Main loop begins here. */
	for (;;) {
		int nfds;

		errno = 0;
		FD_ZERO(&readfds);
		maxfds = 0;

#ifndef TESTING
		/*
		 * Add the Unix Domain Sockets to the list of read
		 * descriptors.
		 */
		/* Copy master connections */
		for (i = 0; i < nfunix; i++) {
			if (funix[i] != -1) {
				FD_SET(funix[i], &readfds);
				if (funix[i] > maxfds)
					maxfds = funix[i];
			}
		}

		/*
		 * Add the Internet Domain Socket to the list of read
		 * descriptors.
		 */
		if (InetInuse && AcceptRemote) {
			for (i = 0; i < *finet; i++) {
				if (finet[i + 1] != -1)
					FD_SET(finet[i + 1], &readfds);
				if (finet[i + 1] > maxfds)
					maxfds = finet[i + 1];
			}
			logit("Listening on syslog UDP port.\n");
		}
#else
		FD_SET(fileno(stdin), &readfds);
		if (fileno(stdin) > maxfds)
			maxfds = fileno(stdin);

		logit("Listening on stdin.  Press Ctrl-C to interrupt.\n");
#endif

		if (debugging_on) {
			logit("Calling select, active file descriptors (max %d): ", maxfds);
			for (nfds = 0; nfds <= maxfds; ++nfds)
				if (FD_ISSET(nfds, &readfds))
					logit("%d ", nfds);
			logit("\n");
		}

		nfds = select(maxfds + 1, &readfds, NULL, NULL, NULL);
		if (restart) {
			restart = 0;
			logit("\nReceived SIGHUP, reloading syslogd.\n");
			init();
#ifndef TESTING
			if (check_pid(PidFile)) {
				if (touch_pid(PidFile))
					logerror("Not possible to touch pidfile");
			} else {
				if (!write_pid(PidFile))
					logerror("Failed to write pidfile");
			}
#endif
			continue;
		}

		if (nfds == 0) {
			logit("No select activity.\n");
			continue;
		}
		if (nfds < 0) {
			if (errno != EINTR)
				logerror("select");
			logit("Select interrupted.\n");
			continue;
		}

		if (debugging_on) {
			logit("\nSuccessful select, descriptor count = %d, "
			      "Activity on: ",
			      nfds);
			for (nfds = 0; nfds <= maxfds; ++nfds)
				if (FD_ISSET(nfds, &readfds))
					logit("%d ", nfds);
			logit("\n");
		}

#ifndef TESTING
		for (i = 0; i < nfunix; i++) {
			if ((fd = funix[i]) != -1 && FD_ISSET(fd, &readfds)) {
				memset(line, 0, sizeof(line));
				msglen = recv(fd, line, MAXLINE - 2, 0);
				logit("Message from UNIX socket: #%d\n", fd);
				if (msglen > 0)
					printchopped(LocalHostName, line, msglen + 2, fd);
				else if (msglen < 0 && errno != EINTR) {
					logit("UNIX socket error: %d = %s.\n",
					      errno, strerror(errno));
					logerror("recvfrom UNIX");
				}
			}
		}

		if (InetInuse && AcceptRemote && finet) {
			for (i = 0; i < *finet; i++) {
				if (finet[i + 1] != -1 && FD_ISSET(finet[i + 1], &readfds)) {
					len = sizeof(frominet);
					memset(line, 0, sizeof(line));
					msglen = recvfrom(finet[i + 1], line, MAXLINE - 2, 0,
					                  (struct sockaddr *)&frominet, &len);
					if (Debug) {
						const char *addr = cvtaddr(&frominet, len);
						logit("Message from inetd socket: #%d, host: %s\n",
						      i + 1, addr);
					}
					if (msglen > 0) {
						const char *from;

						/* Note that if cvthname() returns NULL then
						   we shouldn't attempt to log the line -- jch */
						from = cvthname(&frominet, len);
						if (from)
							printchopped(from, line,
							             msglen + 2, finet[i + 1]);
					} else if (msglen < 0 && errno != EINTR && errno != EAGAIN) {
						logit("INET socket error: %d = %s.\n",
						      errno, strerror(errno));
						logerror("recvfrom inet");
						/* should be harmless now that we set
						 * BSDCOMPAT on the socket */
						sleep(1);
					}
				}
			}
		}
#else
                if (FD_ISSET(fileno(stdin), &readfds)) {
                        logit("Message from stdin.\n");
                        memset(line, 0, sizeof(line));
                        line[0] = '.';
                        parts[fileno(stdin)] = NULL;
                        i = read(fileno(stdin), line, MAXLINE);
                        if (i > 0) {
                                printchopped(LocalHostName, line, i + 1, fileno(stdin));
                        } else if (i < 0) {
                                if (errno != EINTR)
                                        logerror("stdin");
                        } else {
				logit("EOF\n");
				exit(0);
			}
                }

#endif
	}
}

int usage(int code)
{
	fprintf(stdout,
	        "Usage:\n"
	        "  syslogd [-46Adnrvh?] [-a SOCK] [-b SIZE] [-c COUNT] [-f FILE] [-l HOST]\n"
	        "                       [-m SEC]  [-p PATH] [-s LIST]\n"
	        "\n"
	        "Options:\n"
	        "  -?        Show this help text\n"
	        "  -4        Force IPv4 only\n"
	        "  -6        Force IPv6 only\n"
	        "  -a SOCK   Additional socket (max 19) to listen to, used with chroots\n"
	        "  -A        Send to all addresses in DNS A, or AAAA record\n"
	        "  -b SIZE   Log file rotation, rotate at SIZE bytes, default: disabled\n"
	        "  -c COUNT  Number of rotated log files kept\n"
	        "  -d        Enable debug mode\n"
	        "  -f FILE   Alternate .conf file, default: /etc/syslog.conf\n"
	        "  -h        Forward messages from other hosts also to remote syslog host(s)\n"
	        "  -l HOST   Host name to log without its FQDN, use ':' for multiple hosts\n"
	        "  -m INTV   Interval between MARK messages in log, 0 to disable, default: 20\n"
	        "  -n        Run in foreground, required when run from a modern init/supervisor\n"
	        "  -p PATH   Alternate path to UNIX domain socket, default: %s\n"
	        "  -r        Act as remote syslog sink for other hosts\n"
	        "  -s NAME   Strip domain name before logging, use ':' for multiple domains\n"
	        "  -v        Show program version and exit\n"
	        "\n"
	        "Bug report address: %s\n",
		_PATH_LOG, PACKAGE_BUGREPORT);
	exit(code);
}

/*
 * From FreeBSD syslogd SVN r259368
 * https://svnweb.freebsd.org/base/stable/10/usr.sbin/syslogd/syslogd.c?r1=256281&r2=259368
 */
static void increase_rcvbuf(int fd)
{
	socklen_t len, slen;

	slen = sizeof(len);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &len, &slen))
		return;

	if (len < RCVBUF_MINSIZE) {
		len = RCVBUF_MINSIZE;
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len));
	}
}

static int create_unix_socket(const char *path)
{
	struct sockaddr_un sunx;
	char line[MAXLINE + 1];
	int fd;

	if (path[0] == '\0')
		return -1;

	(void)unlink(path);

	memset(&sunx, 0, sizeof(sunx));
	sunx.sun_family = AF_UNIX;
	(void)strncpy(sunx.sun_path, path, sizeof(sunx.sun_path));
	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)&sunx, sizeof(sunx.sun_family) + strlen(sunx.sun_path)) < 0 ||
	    chmod(path, 0666) < 0) {
		(void)snprintf(line, sizeof(line), "cannot create %s", path);
		logerror(line);
		logit("cannot create %s (%d).\n", path, errno);
		close(fd);
		return -1;
	}

	increase_rcvbuf(fd);

	return fd;
}

static int *create_inet_sockets(void)
{
	struct addrinfo hints, *res, *r;
	int error, maxs, *s, *socks;
	int on = 1, sockflags;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(NULL, "syslog", &hints, &res);
	if (error) {
		logerror("network logging disabled (syslog/udp service unknown).");
		logerror("see syslogd(8) for details of whether and how to enable it.");
		logerror(gai_strerror(error));
		return NULL;
	}

	/* Count max number of sockets we may open */
	for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
		;
	socks = malloc((maxs + 1) * sizeof(int));
	if (!socks) {
		logerror("couldn't allocate memory for sockets");
		die(0);
	}

	*socks = 0; /* num of sockets counter at start of array */
	s = socks + 1;
	for (r = res; r; r = r->ai_next) {
		*s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (*s < 0) {
			logerror("socket");
			continue;
		}
		if (r->ai_family == AF_INET6) {
			if (setsockopt(*s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
				logerror("setsockopt (IPV6_ONLY), suspending IPv6");
				close(*s);
				continue;
			}
		}
		if (setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			logerror("setsockopt(REUSEADDR), suspending inet");
			close(*s);
			continue;
		}

		increase_rcvbuf(*s);

		/* We must not block on the network socket, in case a packet
		 * gets lost between select and recv, otherise the process
		 * will stall until the timeout, and other processes trying to
		 * log will also stall.
		 */
		if ((sockflags = fcntl(*s, F_GETFL)) != -1) {
			sockflags |= O_NONBLOCK;
			/*
			 * SETFL could fail too, so get it caught by the subsequent
			 * error check.
			 */
			sockflags = fcntl(*s, F_SETFL, sockflags);
		}
		if (sockflags == -1) {
			logerror("fcntl(O_NONBLOCK), suspending inet");
			close(*s);
			continue;
		}
		if (bind(*s, r->ai_addr, r->ai_addrlen) < 0) {
			logerror("bind, suspending inet");
			close(*s);
			continue;
		}
		(*socks)++;
		s++;
	}
	if (res)
		freeaddrinfo(res);
	if (*socks == 0) {
		logerror("no valid sockets, suspending inet");
		free(socks);
		return NULL;
	}
	return socks;
}

char **crunch_list(list) char *list;
{
	char **result = NULL;
	char *p, *q;
	int i, m, n;

	p = list;

	/* strip off trailing delimiters */
	while (*p && p[strlen(p) - 1] == LIST_DELIMITER)
		p[strlen(p) - 1] = '\0';
	/* cut off leading delimiters */
	while (p[0] == LIST_DELIMITER)
		p++;

	/* count delimiters to calculate the number of elements */
	for (n = i = 0; p[i]; i++)
		if (p[i] == LIST_DELIMITER)
			n++;

	if ((result = (char **)malloc(sizeof(char *) * (n + 2))) == NULL) {
		printf("Sorry, can't get enough memory, exiting.\n");
		exit(1);
	}

	/*
	 * We now can assume that the first and last
	 * characters are different from any delimiters,
	 * so we don't have to care about this.
	 */
	m = 0;
	while ((q = strchr(p, LIST_DELIMITER)) && m < n) {
		result[m] = (char *)malloc((q - p + 1) * sizeof(char));
		if (result[m] == NULL) {
			printf("Sorry, can't get enough memory, exiting.\n");
			exit(1);
		}
		memcpy(result[m], p, q - p);
		result[m][q - p] = '\0';
		p = q;
		p++;
		m++;
	}
	if ((result[m] = strdup(p)) == NULL) {
		printf("Sorry, can't get enough memory, exiting.\n");
		exit(1);
	}
	result[++m] = NULL;

#if 0
	m = 0;
	while (result[m])
		logit("#%d: %s\n", m, result[m++]);
#endif
	return result;
}

void untty(void)
{
	if (!Debug)
		setsid();
}

/*
 * Parse the line to make sure that the msg is not a composite of more
 * than one message.
 */
void printchopped(const char *hname, char *msg, size_t len, int fd)
{
	char tmpline[MAXLINE + 1];
	char *start = msg;
	char *p, *end;
	int ptlngth;

	logit("Message length: %d, File descriptor: %d.\n", len, fd);
	tmpline[0] = '\0';
	if (parts[fd] != NULL) {
		logit("Including part from messages.\n");
		strcpy(tmpline, parts[fd]);
		free(parts[fd]);
		parts[fd] = NULL;
		if ((strlen(msg) + strlen(tmpline)) > MAXLINE) {
			logerror("Cannot glue message parts together");
			printline(hname, tmpline);
			start = msg;
		} else {
			logit("Previous: %s\n", tmpline);
			logit("Next: %s\n", msg);
			strcat(tmpline, msg); /* length checked above */
			printline(hname, tmpline);
			if ((strlen(msg) + 1) == len)
				return;

			start = strchr(msg, '\0') + 1;
		}
	}

	if (msg[len - 1] != '\0') {
		msg[len] = '\0';
		for (p = msg + len - 1; *p != '\0' && p > msg;)
			--p;
		if (*p == '\0')
			p++;
		ptlngth = strlen(p);
		if ((parts[fd] = malloc(ptlngth + 1)) == NULL)
			logerror("Cannot allocate memory for message part.");
		else {
			strcpy(parts[fd], p);
			logit("Saving partial msg: %s\n", parts[fd]);
			memset(p, 0, ptlngth);
		}
	}

	do {
		end = strchr(start + 1, '\0');
		printline(hname, start);
		start = end + 1;
	} while (*start != '\0');
}

/*
 * Take a raw input line, decode the message, and print the message
 * on the appropriate log files.
 */
void printline(const char *hname, char *msg)
{
	unsigned char c;
	unsigned int pri;       /* Valid Priority values are 0-191 */
	char *p, *q;
	char line[MAXLINE + 1];
	int prilen = 0;         /* Track Priority value string len */
	int msglen;

	/* test for special codes */
	msglen = strlen(msg);
	pri = DEFUPRI;
	p = msg;

	if (*p == '<') {
		pri = 0;
		while (--msglen > 0 && isdigit((unsigned char)*++p) &&
		       pri <= MAX_PRI) {
			pri = 10 * pri + (*p - '0');
			prilen++;
		}
		if (*p == '>' && prilen)
			++p;
		else {
			pri = DEFUPRI;
			p = msg;
		}
	}

	if ((pri & ~(LOG_FACMASK | LOG_PRIMASK)) || (pri > MAX_PRI)) {
		pri = DEFUPRI;
		p = msg;
	}

	memset(line, 0, sizeof(line));
	q = line;
	while ((c = *p++) && q < &line[sizeof(line) - 4]) {
		if (c == '\n' || c == 127)
			*q++ = ' ';
		else if (c < 040) {
			*q++ = '^';
			*q++ = c ^ 0100;
		} else
			*q++ = c;
	}
	*q = '\0';

	logmsg(pri, line, hname, SYNC_FILE);
}

/*
 * Take a raw input line from /dev/klog, split and format similar to syslog().
 */
void printsys(char *msg)
{
	char line[MAXLINE + 1];
	char *lp, *p, *q;
	int c, pri, flags;

	(void)snprintf(line, sizeof(line), "vmunix: ");
	lp = line + strlen(line);
	for (p = msg; *p != '\0';) {
		flags = ADDDATE;
		pri = DEFSPRI;

		if (*p == '<') {
			pri = 0;
			while (isdigit(*++p))
				pri = 10 * pri + (*p - '0');
			if (*p == '>')
				++p;
		} else {
			/* kernel printf's come out on console */
			flags |= IGN_CONS;
		}

		if (pri & ~(LOG_FACMASK | LOG_PRIMASK))
			pri = DEFSPRI;

		q = lp;
		while (*p != '\0' && (c = *p++) != '\n' &&
		       q < &line[MAXLINE])
			*q++ = c;
		*q = '\0';
		logmsg(pri, line, LocalHostName, flags);
	}
}

/*
 * Decode a priority into textual information like auth.emerg.
 */
char *textpri(int pri)
{
	static char res[20];
	CODE *c_pri, *c_fac;

	for (c_fac = facilitynames; c_fac->c_name && !(c_fac->c_val == LOG_FAC(pri) << 3); c_fac++)
		;
	for (c_pri = prioritynames; c_pri->c_name && !(c_pri->c_val == LOG_PRI(pri)); c_pri++)
		;

	snprintf(res, sizeof(res), "%s.%s<%d>", c_fac->c_name, c_pri->c_name, pri);

	return res;
}

time_t now;

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */
void logmsg(int pri, char *msg, const char *from, int flags)
{
	struct filed *f;
	sigset_t mask;
	char *timestamp;
	int fac, prilev, msglen;

	logit("logmsg: %s, flags %x, from %s, msg %s\n", textpri(pri), flags, from, msg);

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGALRM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	/*
	 * Check to see if msg looks non-standard.
	 *
	 * A message looks like
	 * Nov 17 11:42:33 CRON[
	 * 01234567890123456
	 *    ^  ^  ^  ^  ^
	 *
	 * Remote messages are not accompanied by a timestamp.
	 * Local messages are accompanied by a timestamp (program's timezone)
	 */
	msglen = strlen(msg);
	if (!(msglen < 16 || msg[3] != ' ' || msg[6] != ' ' ||
	      msg[9] != ':' || msg[12] != ':' || msg[15] != ' ')) {
		msg += 16;
		msglen -= 16;
	}

	(void)time(&now);
	timestamp = ctime(&now) + 4;

	/* extract facility and priority level */
	fac = LOG_FAC(pri);
	prilev = LOG_PRI(pri);

	/* log the message to the particular outputs */
	if (!Initialized) {
		f = &consfile;
		f->f_file = open(ctty, O_WRONLY | O_NOCTTY);

		if (f->f_file >= 0) {
			untty();
			fprintlog(f, (char *)from, flags, msg);
			(void)close(f->f_file);
			f->f_file = -1;
		}

		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		return;
	}

	for (f = Files; f; f = f->f_next) {
		/* skip messages that are incorrect priority */
		if ((f->f_pmask[fac] == TABLE_NOPRI) ||
		    ((f->f_pmask[fac] & (1 << prilev)) == 0))
			continue;

		if (f->f_type == F_CONSOLE && (flags & IGN_CONS))
			continue;

		/* don't output marks to recently written files */
		if ((flags & MARK) && (now - f->f_time) < MarkInterval / 2)
			continue;

		/*
		 * suppress duplicate lines to this file
		 */
		if ((flags & MARK) == 0 && msglen == f->f_prevlen &&
		    !strcmp(msg, f->f_prevline) &&
		    !strcmp(from, f->f_prevhost)) {
			(void)strncpy(f->f_lasttime, timestamp, 15);
			f->f_prevcount++;
			logit("msg repeated %d times, %ld sec of %d.\n",
			      f->f_prevcount, now - f->f_time,
			      repeatinterval[f->f_repeatcount]);

			if (f->f_prevcount == 1 && DupesPending++ == 0) {
				int seconds;
				logit("setting alarm to flush duplicate messages\n");

				seconds = alarm(0);
				MarkSeq += LastAlarm - seconds;
				LastAlarm = seconds;
				if (LastAlarm > TIMERINTVL)
					LastAlarm = TIMERINTVL;
				alarm(LastAlarm);
			}

			/*
			 * If domark would have logged this by now,
			 * flush it now (so we don't hold isolated messages),
			 * but back off so we'll flush less often
			 * in the future.
			 */
			if (now > REPEATTIME(f)) {
				fprintlog(f, (char *)from, flags, (char *)NULL);
				BACKOFF(f);
			}
		} else {
			/* new line, save it */
			if (f->f_prevcount) {
				fprintlog(f, (char *)from, 0, (char *)NULL);

				if (--DupesPending == 0) {
					logit("unsetting duplicate message flush alarm\n");

					MarkSeq += LastAlarm - alarm(0);
					LastAlarm = MarkInterval - MarkSeq;
					alarm(LastAlarm);
				}
			}
			f->f_prevpri = pri;
			f->f_repeatcount = 0;
			(void)strncpy(f->f_lasttime, timestamp, 15);
			(void)strncpy(f->f_prevhost, from,
			              sizeof(f->f_prevhost));
			if (msglen < MAXSVLINE) {
				f->f_prevlen = msglen;
				(void)strcpy(f->f_prevline, msg);
				fprintlog(f, (char *)from, flags, (char *)NULL);
			} else {
				f->f_prevline[0] = 0;
				f->f_prevlen = 0;
				fprintlog(f, (char *)from, flags, msg);
			}
		}
	}

	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

void logrotate(struct filed *f)
{
	struct stat statf;

	if (!f->f_rotatesz)
		return;

	fstat(f->f_file, &statf);
	/* bug (mostly harmless): can wrap around if file > 4gb */
	if (S_ISREG(statf.st_mode) && statf.st_size > f->f_rotatesz) {
		if (f->f_rotatecount > 0) { /* always 0..999 */
			int  len = strlen(f->f_un.f_fname) + 10 + 5;
			int  i;
			char oldFile[len];
			char newFile[len];

			/* First age zipped log files */
			for (i = f->f_rotatecount; i > 1; i--) {
				snprintf(oldFile, len, "%s.%d.gz", f->f_un.f_fname, i - 1);
				snprintf(newFile, len, "%s.%d.gz", f->f_un.f_fname, i);

				/* ignore errors - file might be missing */
				(void)rename(oldFile, newFile);
			}

			/* rename: f.8 -> f.9; f.7 -> f.8; ... */
			for (i = 1; i > 0; i--) {
				sprintf(oldFile, "%s.%d", f->f_un.f_fname, i - 1);
				sprintf(newFile, "%s.%d", f->f_un.f_fname, i);

				if (!rename(oldFile, newFile) && i > 0) {
					size_t len = 18 + strlen(newFile) + 1;
					char cmd[len];

					snprintf(cmd, sizeof(cmd), "gzip -f %s", newFile);
					system(cmd);
				}
			}

			/* newFile == "f.0" now */
			sprintf(newFile, "%s.0", f->f_un.f_fname);
			rename(f->f_un.f_fname, newFile);
			close(f->f_file);
			f->f_file = open(f->f_un.f_fname, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_NOCTTY, 0644);
		}
		ftruncate(f->f_file, 0);
	}
}

/*
 * Trims the application name ("TAG" in RFC 3164 terminology) and
 * process ID from a message if present.
 */
static void
parsemsg_rfc3164_app_name_procid(char **msg, char **app_name, char **procid)
{
	char *m, *app_name_begin, *procid_begin;
	size_t app_name_length, procid_length;

	m = *msg;

	/* Application name. */
	app_name_begin = m;
	app_name_length = strspn(m,
	    "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789"
	    "_-/");
	if (app_name_length == 0)
		goto bad;
	m += app_name_length;

	/* Process identifier (optional). */
	if (*m == '[') {
		procid_begin = ++m;
		procid_length = strspn(m, "0123456789");
		if (procid_length == 0)
			goto bad;
		m += procid_length;
		if (*m++ != ']')
			goto bad;
	} else {
		procid_begin = NULL;
		procid_length = 0;
	}

	/* Separator. */
	if (m[0] != ':' || m[1] != ' ')
		goto bad;

	/* Split strings from input. */
	app_name_begin[app_name_length] = '\0';
	if (procid_begin != 0)
		procid_begin[procid_length] = '\0';

	*msg = m + 2;
	*app_name = app_name_begin;
	*procid = procid_begin;
	return;
bad:
	*app_name = NULL;
	*procid = NULL;
}

/*
 * Currently unsupported RFC 5424 fields: msgid, structured_data
 */
static void fmt5424(char *line, size_t len, int pri, char *msg)
{
	struct logtime *timestamp = NULL;
	struct logtime timestamp_now;
	struct timeval tv;
	suseconds_t usec;
	char *structured_data = NULL;
	char *app_name = NULL;
	char *procid = NULL;
	char *msgid = NULL;
	char hostname[256];
	char timebuf[33];

	parsemsg_rfc3164_app_name_procid(&msg, &app_name, &procid);

	gethostname(hostname, sizeof(hostname));

	(void)gettimeofday(&tv, NULL);
	now = tv.tv_sec;

	if (timestamp == NULL) {
		localtime_r(&now, &timestamp_now.tm);
		timestamp_now.usec = tv.tv_usec;
		timestamp = &timestamp_now;
	}

	strftime(timebuf, sizeof(timebuf), "%FT%T.______%z", &timestamp->tm);

	/* Add colon to the time zone offset, which %z doesn't do */
	timebuf[32] = '\0';
	timebuf[31] = timebuf[30];
	timebuf[30] = timebuf[29];
	timebuf[29] = ':';

	/* Overwrite space for microseconds with actual value */
	usec = timestamp->usec;
	for (int i = 25; i >= 20; --i) {
		timebuf[i] = usec % 10 + '0';
		usec /= 10;
	}

	snprintf(line, len, "<%d>1 %s %s %s %s %s %s %s",
		 pri, timebuf, hostname,
		 app_name == NULL ? "-" : app_name,
		 procid == NULL ? "-" : procid,
		 msgid == NULL ? "-" : msgid,
		 structured_data == NULL ? "-" : structured_data,
		 msg);
}

void fprintlog(struct filed *f, char *from, int flags, char *msg)
{
	struct iovec iov[6];
	struct iovec *v = iov;
	char repbuf[80];
	struct addrinfo hints, *ai;
	time_t fwd_suspend;
	char line[MAXLINE + 1];
	int l, err;

	logit("Called fprintlog, ");

	v->iov_base = f->f_lasttime;
	v->iov_len = 15;
	v++;
	v->iov_base = " ";
	v->iov_len = 1;
	v++;
	v->iov_base = f->f_prevhost;
	v->iov_len = strlen(v->iov_base);
	v++;
	v->iov_base = " ";
	v->iov_len = 1;
	v++;
	if (msg) {
		v->iov_base = msg;
		v->iov_len = strlen(msg);
	} else if (f->f_prevcount > 1) {
		(void)snprintf(repbuf, sizeof(repbuf), "last message repeated %d times",
		               f->f_prevcount);
		v->iov_base = repbuf;
		v->iov_len = strlen(repbuf);
	} else {
		v->iov_base = f->f_prevline;
		v->iov_len = f->f_prevlen;
	}
	v++;

	logit("logging to %s", TypeNames[f->f_type]);

	switch (f->f_type) {
	case F_UNUSED:
		f->f_time = now;
		logit("\n");
		break;

	case F_FORW_SUSP:
		fwd_suspend = time(NULL) - f->f_time;
		if (fwd_suspend >= INET_SUSPEND_TIME) {
			logit("\nForwarding suspension over, "
			      "retrying FORW ");
			f->f_type = F_FORW;
			goto f_forw;
		} else {
			logit(" %s\n", f->f_un.f_forw.f_hname);
			logit("Forwarding suspension not over, time "
			      "left: %d.\n",
			      INET_SUSPEND_TIME - fwd_suspend);
		}
		break;

	/*
	 * The trick is to wait some time, then retry to get the
	 * address. If that fails retry x times and then give up.
	 *
	 * You'll run into this problem mostly if the name server you
	 * need for resolving the address is on the same machine, but
	 * is started after syslogd. 
	 */
	case F_FORW_UNKN:
		logit(" %s\n", f->f_un.f_forw.f_hname);
		fwd_suspend = time(NULL) - f->f_time;
		if (fwd_suspend >= INET_SUSPEND_TIME) {
			logit("Forwarding suspension to unknown over, retrying\n");
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = family;
			hints.ai_socktype = SOCK_DGRAM;
			if ((err = getaddrinfo(f->f_un.f_forw.f_hname, "syslog", &hints, &ai))) {
				logit("Failure: %s\n", gai_strerror(err));
				logit("Retries: %d\n", f->f_prevcount);
				if (--f->f_prevcount < 0) {
					logit("Giving up.\n");
					f->f_type = F_UNUSED;
				} else
					logit("Left retries: %d\n", f->f_prevcount);
			} else {
				logit("%s found, resuming.\n", f->f_un.f_forw.f_hname);
				f->f_un.f_forw.f_addr = ai;
				f->f_prevcount = 0;
				f->f_type = F_FORW;
				goto f_forw;
			}
		} else
			logit("Forwarding suspension not over, time "
			      "left: %d\n",
			      INET_SUSPEND_TIME - fwd_suspend);
		break;

	case F_FORW:
		/* 
		 * Don't send any message to a remote host if it
		 * already comes from one. (we don't care 'bout who
		 * sent the message, we don't send it anyway)  -Joey
		 */
	f_forw:
		logit(" %s\n", f->f_un.f_forw.f_hname);
		if (strcmp(from, LocalHostName) && NoHops)
			logit("Not sending message to remote.\n");
		else if (finet) {
			int i;
			f->f_time = now;
			if (f->f_flags & RFC5424)
				fmt5424(line, sizeof(line), f->f_prevpri,
					(char *)iov[4].iov_base);
			else
				snprintf(line, sizeof(line), "<%d>%s", f->f_prevpri,
					 (char *)iov[4].iov_base);
			l = strlen(line);
			if (l > MAXLINE)
				l = MAXLINE;
			err = -1;
			for (ai = f->f_un.f_forw.f_addr; ai; ai = ai->ai_next) {
				for (i = 0; i < *finet; i++) {
					int lsent;
					lsent = sendto(finet[i + 1], line, l, 0,
					               ai->ai_addr, ai->ai_addrlen);
					if (lsent == l) {
						err = -1;
						break;
					}
					err = errno;
				}
				if (err == -1 && !send_to_all)
					break;
			}
			if (err != -1) {
				logit("INET sendto error: %d = %s.\n",
				      err, strerror(err));
				f->f_type = F_FORW_SUSP;
				errno = err;
				logerror("sendto");
			}
		}
		break;

	case F_CONSOLE:
		f->f_time = now;
		if (flags & IGN_CONS) {
			logit(" (ignored).\n");
			break;
		}
		/* FALLTHROUGH */

	case F_TTY:
	case F_FILE:
	case F_PIPE:
		f->f_time = now;
		logit(" %s\n", f->f_un.f_fname);
		if (f->f_type == F_TTY || f->f_type == F_CONSOLE) {
			v->iov_base = "\r\n";
			v->iov_len = 2;
		} else {
			v->iov_base = "\n";
			v->iov_len = 1;
		}
	again:
		/* f->f_file == -1 is an indicator that we couldn't
		   open the file at startup. */
		if (f->f_file == -1)
			break;

		if (f->f_type == F_FILE)
			logrotate(f);

		if (writev(f->f_file, iov, 6) < 0) {
			int e = errno;

			/* If a named pipe is full, just ignore it for now */
			if (f->f_type == F_PIPE && e == EAGAIN)
				break;

			/* If the filesystem is filled up, just ignore
			   it for now and continue writing when
			   possible */
			if (f->f_type == F_FILE && e == ENOSPC)
				break;

			/*
			 * If the console is backed up, just ignore it
			 * and continue writing again when possible.
			 */
			if (f->f_type == F_CONSOLE && e == EAGAIN)
				break;

			(void)close(f->f_file);
			/*
			 * Check for EBADF/EIO on TTY's due to vhangup()
			 */
			if ((f->f_type == F_TTY || f->f_type == F_CONSOLE) && e == EHANGUP) {
				f->f_file = open(f->f_un.f_fname, O_WRONLY | O_APPEND | O_NOCTTY);
				if (f->f_file < 0) {
					f->f_type = F_UNUSED;
					logerror(f->f_un.f_fname);
				} else {
					untty();
					goto again;
				}
			} else {
				f->f_type = F_UNUSED;
				errno = e;
				logerror(f->f_un.f_fname);
			}
		} else if (f->f_type == F_FILE && (f->f_flags & SYNC_FILE))
			(void)fsync(f->f_file);
		break;

	case F_USERS:
	case F_WALL:
		f->f_time = now;
		logit("\n");
		v->iov_base = "\r\n";
		v->iov_len = 2;
		wallmsg(f, iov);
		break;
	} /* switch */

	if (f->f_type != F_FORW_UNKN)
		f->f_prevcount = 0;
}

jmp_buf ttybuf;

void endtty(int signo)
{
	longjmp(ttybuf, 1);
}

/*
 *  WALLMSG -- Write a message to the world at large
 *
 *	Write the specified message to either the entire
 *	world, or a list of approved users.
 */
void wallmsg(struct filed *f, struct iovec *iov)
{
	static int reenter = 0;
	struct utmp *uptr;
	struct utmp  ut;
	char p[sizeof(_PATH_DEV) + UNAMESZ];
	char greetings[200];
	int ttyf, len, i;

	(void)&len;

	if (reenter++)
		return;

	/* open the user login file */
	setutent();

	/*
	 * Might as well fork instead of using nonblocking I/O
	 * and doing notty().
	 */
	if (fork() == 0) {
		(void)signal(SIGTERM, SIG_DFL);
		(void)alarm(0);

		(void)snprintf(greetings, sizeof(greetings),
		               "\r\n\7Message from syslogd@%s at %.24s ...\r\n",
		               (char *)iov[2].iov_base, ctime(&now));
		len = strlen(greetings);

		/* scan the user login file */
		while ((uptr = getutent())) {
			memcpy(&ut, uptr, sizeof(ut));
			/* is this slot used? */
			if (ut.ut_name[0] == '\0')
				continue;
			if (ut.ut_type != USER_PROCESS)
				continue;
			if (!(strcmp(ut.ut_name, "LOGIN"))) /* paranoia */
				continue;

			/* should we send the message to this user? */
			if (f->f_type == F_USERS) {
				for (i = 0; i < MAXUNAMES; i++) {
					if (!f->f_un.f_uname[i][0]) {
						i = MAXUNAMES;
						break;
					}
					if (strncmp(f->f_un.f_uname[i],
					            ut.ut_name, UNAMESZ) == 0)
						break;
				}
				if (i >= MAXUNAMES)
					continue;
			}

			/* compute the device name */
			strcpy(p, _PATH_DEV);
			strncat(p, ut.ut_line, UNAMESZ);

			if (f->f_type == F_WALL) {
				iov[0].iov_base = greetings;
				iov[0].iov_len = len;
				iov[1].iov_len = 0;
			}
			if (setjmp(ttybuf) == 0) {
				(void)signal(SIGALRM, endtty);
				(void)alarm(15);
				/* open the terminal */
				ttyf = open(p, O_WRONLY | O_NOCTTY);
				if (ttyf >= 0) {
					struct stat statb;

					if (fstat(ttyf, &statb) == 0 &&
					    (statb.st_mode & S_IWRITE))
						(void)writev(ttyf, iov, 6);
					close(ttyf);
					ttyf = -1;
				}
			}
			(void)alarm(0);
		}
		exit(0);
	}
	/* close the user login file */
	endutent();
	reenter = 0;
}

void reapchild(int signo)
{
	int saved_errno;
	int status;

	saved_errno = errno;
	while (waitpid(-1, &status, WNOHANG) > 0)
		;

	errno = saved_errno;
}

const char *cvtaddr(struct sockaddr_storage *f, int len)
{
	static char ip[NI_MAXHOST];

	if (getnameinfo((struct sockaddr *)f, len,
	                ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
		return "???";
	return ip;
}

/*
 * Return a printable representation of a host address.
 *
 * Here we could check if the host is permitted to send us syslog
 * messages.  We just have to check the hostname we're about to return
 * and compared it (case-insensitively) to a blacklist or whitelist.
 * Callers of cvthname() need to know that if NULL is returned then
 * the host is to be ignored.
 */
const char *cvthname(struct sockaddr_storage *f, int len)
{
	static char hname[NI_MAXHOST];
	char *p;
	int error, count;

	if ((error = getnameinfo((struct sockaddr *)f, len,
	                         hname, NI_MAXHOST, NULL, 0, NI_NAMEREQD))) {
		logit("Host name for your address (%s) unknown: %s\n", gai_strerror(error));
		if ((error = getnameinfo((struct sockaddr *)f, len,
		                         hname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))) {
			logit("Malformed from address: %s\n", gai_strerror(error));
			return "???";
		}
		return hname;
	}
	/*
	 * Convert to lower case, just like LocalDomain above
	 */
	for (p = hname; *p; p++) {
		if (isupper(*p))
			*p = tolower(*p);
	}

	/*
	 * Notice that the string still contains the fqdn, but your
	 * hostname and domain are separated by a '\0'.
	 */
	if ((p = strchr(hname, '.'))) {
		if (strcmp(p + 1, LocalDomain) == 0) {
			*p = '\0';
			return hname;
		} else {
			if (StripDomains) {
				count = 0;
				while (StripDomains[count]) {
					if (strcmp(p + 1, StripDomains[count]) == 0) {
						*p = '\0';
						return hname;
					}
					count++;
				}
			}
			if (LocalHosts) {
				count = 0;
				while (LocalHosts[count]) {
					if (!strcmp(hname, LocalHosts[count])) {
						*p = '\0';
						return hname;
					}
					count++;
				}
			}
		}
	}

	return hname;
}

void domark(int signo)
{
	struct filed *f;

	if (MarkInterval > 0) {
		now = time(0);
		MarkSeq += LastAlarm;
		if (MarkSeq >= MarkInterval) {
			logmsg(LOG_MARK | LOG_INFO, "-- MARK --", LocalHostName, ADDDATE | MARK);
			MarkSeq -= MarkInterval;
		}
	}

	for (f = Files; f; f = f->f_next) {
		if (f->f_prevcount && now >= REPEATTIME(f)) {
			logit("flush %s: repeated %d times, %d sec.\n",
			      TypeNames[f->f_type], f->f_prevcount,
			      repeatinterval[f->f_repeatcount]);
			fprintlog(f, LocalHostName, 0, (char *)NULL);
			BACKOFF(f);
			DupesPending--;
		}
	}

	LastAlarm = MarkInterval - MarkSeq;
	if (DupesPending && LastAlarm > TIMERINTVL)
		LastAlarm = TIMERINTVL;

	(void)alarm(LastAlarm);
}

void debug_switch(int signo)
{
	logit("Switching debugging_on to %s\n", (debugging_on == 0) ? "true" : "false");
	debugging_on = (debugging_on == 0) ? 1 : 0;
	signal(SIGUSR1, debug_switch);
}

/*
 * Print syslogd errors some place.
 */
void logerror(const char *type)
{
	char buf[100];

	logit("Called logerr, msg: %s\n", type);

	if (errno == 0)
		(void)snprintf(buf, sizeof(buf), "syslogd: %s", type);
	else
		(void)snprintf(buf, sizeof(buf), "syslogd: %s: %s", type, strerror(errno));
	errno = 0;
	logmsg(LOG_SYSLOG | LOG_ERR, buf, LocalHostName, ADDDATE);
}

void die(int signo)
{
	struct filed *f;
	char buf[100];
	int lognum;
	int i;
	int was_initialized = Initialized;

	Initialized = 0; /* Don't log SIGCHLDs in case we
			    receive one during exiting */

	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog(f, LocalHostName, 0, (char *)NULL);
	}

	Initialized = was_initialized;
	if (signo) {
		logit("syslogd: exiting on signal %d\n", signo);
		(void)snprintf(buf, sizeof(buf), "exiting on signal %d", signo);
		errno = 0;
		logmsg(LOG_SYSLOG | LOG_INFO, buf, LocalHostName, ADDDATE);
	}

	/* Close the UNIX sockets. */
	for (i = 0; i < nfunix; i++)
		if (funix[i] != -1)
			close(funix[i]);
	/* Close the inet sockets. */
	if (InetInuse && finet) {
		for (i = 0; i < *finet; i++)
			close(finet[i + 1]);
		free(finet);
	}

	/* Clean-up files. */
	for (i = 0; i < nfunix; i++)
		if (funixn[i] && funix[i] != -1)
			(void)unlink(funixn[i]);
#ifndef TESTING
	(void)remove_pid(PidFile);
#endif
	exit(0);
}

/*
 * Signal handler to terminate the parent process.
 */
#ifndef TESTING
void doexit(int signo)
{
	exit(0);
}
#endif

/*
 *  INIT -- Initialize syslogd from configuration table
 */
void init(void)
{
	struct filed **nextp = NULL;
	struct hostent *hent;
	struct filed *f;
	unsigned int Forwarding = 0;
	FILE *cf;
	char  cbuf[BUFSIZ];
	char *cline;
	char *p;
	int i, lognum;

	/*
	 *  Close all open log files and free log descriptor array.
	 */
	logit("Called init.\n");
	Initialized = 0;
	if (nlogs > -1) {
		logit("Initializing log structures.\n");

		for (lognum = 0; lognum <= nlogs; lognum++) {
			f = &Files[lognum];

			/* flush any pending output */
			if (f->f_prevcount)
				fprintlog(f, LocalHostName, 0, (char *)NULL);

			switch (f->f_type) {
			case F_FILE:
			case F_PIPE:
			case F_TTY:
			case F_CONSOLE:
				(void)close(f->f_file);
				break;
			case F_FORW:
			case F_FORW_SUSP:
				freeaddrinfo(f->f_un.f_forw.f_addr);
				break;
			}
		}

		/*
		 * This is needed especially when HUPing syslogd as the
		 * structure would grow infinitively.  -Joey
		 */
		nlogs = -1;
		free((void *)Files);
		Files = NULL;
	}

	f = NULL;

	/* Get hostname */
	(void)gethostname(LocalHostName, sizeof(LocalHostName));
	LocalDomain = emptystring;
	if ((p = strchr(LocalHostName, '.'))) {
		*p++ = '\0';
		LocalDomain = p;
	} else if (AcceptRemote) {
		/*
		 * It's not clearly defined whether gethostname()
		 * should return the simple hostname or the fqdn. A
		 * good piece of software should be aware of both and
		 * we want to distribute good software.  Joey
		 *
		 * Good software also always checks its return values...
		 * If syslogd starts up before DNS is up & /etc/hosts
		 * doesn't have LocalHostName listed, gethostbyname will
		 * return NULL. 
		 */
		hent = gethostbyname(LocalHostName);
		if (hent)
			snprintf(LocalHostName, sizeof(LocalHostName), "%s", hent->h_name);

		if ((p = strchr(LocalHostName, '.'))) {
			*p++ = '\0';
			LocalDomain = p;
		}
	}

	/*
	 * Convert to lower case to recognize the correct domain laterly
	 */
	for (p = (char *)LocalDomain; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);

	/* open the configuration file */
	if ((cf = fopen(ConfFile, "r")) == NULL) {
		logit("cannot open %s.\n", ConfFile);

#ifndef TESTING
		cfline("*.err\t" _PATH_CONSOLE, f);
#else
		snprintf(cbuf, sizeof(cbuf), "*.*\t%s", ttyname(0));
		cfline(cbuf, f);
#endif

		*nextp = calloc(1, sizeof(*f));
		if (!*nextp) {
			logerror("Cannot allocate memory for log target/file");
			return;
		}
		cfline("*.ERR\t" _PATH_CONSOLE, *nextp);

		(*nextp)->f_next = calloc(1, sizeof(*f)); /* ASP */
		if (!*nextp) {
			logerror("Cannot allocate memory for log target/file");
			return;
		}
		cfline("*.PANIC\t*", (*nextp)->f_next);

		Initialized = 1;
		return;
	}

	/*
	 *  Foreach line in the conf table, open that file.
	 */
	cline = cbuf;
	while (fgets(cline, sizeof(cbuf) - (cline - cbuf), cf) != NULL) {
		/*
		 * check for end-of-section, comments, strip off trailing
		 * spaces and newline character.
		 */
		for (p = cline; isspace(*p); ++p)
			;
		if (*p == '\0' || *p == '#')
			continue;

		memmove(cline, p, strlen(p) + 1);
		for (p = strchr(cline, '\0'); isspace(*--p);)
			;

		if (*p == '\\') {
			if ((p - cbuf) > BUFSIZ - 30) {
				/* Oops the buffer is full - what now? */
				cline = cbuf;
			} else {
				*p = 0;
				cline = p;
				continue;
			}
		} else
			cline = cbuf;

		*++p = '\0';

		f = (struct filed *)calloc(1, sizeof(*f));
		if (!f) {
			logerror("Cannot allocate memory for log file");
			return;
		}

		if (!nextp)
			Files = f;
		else
			*nextp = f;
		nextp = &f->f_next;

		cfline(cbuf, f);
		if (f->f_type == F_FORW || f->f_type == F_FORW_SUSP || f->f_type == F_FORW_UNKN) {
			Forwarding++;
		}
	}

	/* close the configuration file */
	(void)fclose(cf);

	for (i = 0; i < nfunix; i++) {
		if (funix[i] != -1)
			/* Don't close the socket, preserve it instead
			close(funix[i]);
			*/
			continue;
		if ((funix[i] = create_unix_socket(funixn[i])) != -1)
			logit("Opened UNIX socket `%s'.\n", funixn[i]);
	}

	if (Forwarding || AcceptRemote) {
		if (!finet) {
			finet = create_inet_sockets();
			if (finet) {
				InetInuse = 1;
				logit("Opened syslog UDP port.\n");
			}
		}
	} else {
		if (finet) {
			for (i = 0; i < *finet; i++)
				if (finet[i + 1] != -1)
					close(finet[i + 1]);
			free(finet);
			finet = NULL;
		}
		InetInuse = 0;
	}

	Initialized = 1;

	if (Debug) {
		for (f = Files; f; f = f->f_next) {
			if (f->f_type != F_UNUSED) {
				for (i = 0; i <= LOG_NFACILITIES; i++)
					if (f->f_pmask[i] == TABLE_NOPRI)
						printf(" X ");
					else
						printf("%2X ", f->f_pmask[i]);
				printf("%s: ", TypeNames[f->f_type]);
				switch (f->f_type) {
				case F_FILE:
				case F_PIPE:
				case F_TTY:
				case F_CONSOLE:
					printf("%s", f->f_un.f_fname);
					if (f->f_file == -1)
						printf(" (unused)");
					break;

				case F_FORW:
				case F_FORW_SUSP:
				case F_FORW_UNKN:
					printf("%s", f->f_un.f_forw.f_hname);
					break;

				case F_USERS:
					for (i = 0; i < MAXUNAMES && *f->f_un.f_uname[i]; i++)
						printf("%s, ", f->f_un.f_uname[i]);
					break;
				}
				printf("\n");
			}
		}
	}

	if (AcceptRemote)
		logmsg(LOG_SYSLOG | LOG_INFO, "syslogd v" VERSION ": restart (remote reception).", LocalHostName,
		       ADDDATE);
	else
		logmsg(LOG_SYSLOG | LOG_INFO, "syslogd v" VERSION ": restart.", LocalHostName, ADDDATE);

	(void)signal(SIGHUP, sighup_handler);
	logit("syslogd: restarted.\n");
}

/*
 * Crack a configuration file line
 */
void cfline(char *line, struct filed *f)
{
	struct addrinfo hints, *ai;
	char buf[MAXLINE];
	char xbuf[MAXLINE + 24];
	char *p, *q, *bp;
	int ignorepri = 0;
	int singlpri = 0;
	int syncfile, pri, i, i2;

	logit("cfline(%s)\n", line);

	errno = 0; /* keep strerror() stuff out of logerror messages */

	/* clear out file entry */
	memset((char *)f, 0, sizeof(*f));
	for (i = 0; i <= LOG_NFACILITIES; i++) {
		f->f_pmask[i] = TABLE_NOPRI;
		f->f_flags = 0;
	}

	/* default rotate from command line */
	f->f_rotatecount = RotateCnt;
	f->f_rotatesz = RotateSz;

	/* scan through the list of selectors */
	for (p = line; *p && *p != '\t' && *p != ' ';) {

		/* find the end of this facility name list */
		for (q = p; *q && *q != '\t' && *q++ != '.';)
			continue;

		/* collect priority name */
		for (bp = buf; *q && !strchr("\t ,;", *q);)
			*bp++ = *q++;
		*bp = '\0';

		/* skip cruft */
		while (strchr(",;", *q))
			q++;

		/* decode priority name */
		if (*buf == '!') {
			ignorepri = 1;
			for (bp = buf; *(bp + 1); bp++)
				*bp = *(bp + 1);
			*bp = '\0';
		} else {
			ignorepri = 0;
		}
		if (*buf == '=') {
			singlpri = 1;
			pri = decode(&buf[1], PriNames);
		} else {
			singlpri = 0;
			pri = decode(buf, PriNames);
		}

		if (pri < 0) {
			(void)snprintf(xbuf, sizeof(xbuf), "unknown priority name \"%s\"", buf);
			logerror(xbuf);
			return;
		}

		/* scan facilities */
		while (*p && !strchr("\t .;", *p)) {
			for (bp = buf; *p && !strchr("\t ,;.", *p);)
				*bp++ = *p++;
			*bp = '\0';
			if (*buf == '*') {
				for (i = 0; i <= LOG_NFACILITIES; i++) {
					if (pri == INTERNAL_NOPRI) {
						if (ignorepri)
							f->f_pmask[i] = TABLE_ALLPRI;
						else
							f->f_pmask[i] = TABLE_NOPRI;
					} else if (singlpri) {
						if (ignorepri)
							f->f_pmask[i] &= ~(1 << pri);
						else
							f->f_pmask[i] |= (1 << pri);
					} else {
						if (pri == TABLE_ALLPRI) {
							if (ignorepri)
								f->f_pmask[i] = TABLE_NOPRI;
							else
								f->f_pmask[i] = TABLE_ALLPRI;
						} else {
							if (ignorepri)
								for (i2 = 0; i2 <= pri; ++i2)
									f->f_pmask[i] &= ~(1 << i2);
							else
								for (i2 = 0; i2 <= pri; ++i2)
									f->f_pmask[i] |= (1 << i2);
						}
					}
				}
			} else {
				i = decode(buf, FacNames);
				if (i < 0) {

					(void)snprintf(xbuf, sizeof(xbuf), "unknown facility name \"%s\"", buf);
					logerror(xbuf);
					return;
				}

				if (pri == INTERNAL_NOPRI) {
					if (ignorepri)
						f->f_pmask[i >> 3] = TABLE_ALLPRI;
					else
						f->f_pmask[i >> 3] = TABLE_NOPRI;
				} else if (singlpri) {
					if (ignorepri)
						f->f_pmask[i >> 3] &= ~(1 << pri);
					else
						f->f_pmask[i >> 3] |= (1 << pri);
				} else {
					if (pri == TABLE_ALLPRI) {
						if (ignorepri)
							f->f_pmask[i >> 3] = TABLE_NOPRI;
						else
							f->f_pmask[i >> 3] = TABLE_ALLPRI;
					} else {
						if (ignorepri)
							for (i2 = 0; i2 <= pri; ++i2)
								f->f_pmask[i >> 3] &= ~(1 << i2);
						else
							for (i2 = 0; i2 <= pri; ++i2)
								f->f_pmask[i >> 3] |= (1 << i2);
					}
				}
			}
			while (*p == ',' || *p == ' ')
				p++;
		}

		p = q;
	}

	/* skip to action part */
	while (*p == '\t' || *p == ' ')
		p++;

	if (*p == '-') {
		syncfile = 0;
		p++;
	} else
		syncfile = 1;

	logit("leading char in action: %c\n", *p);
	switch (*p) {
	case '@':
		bp = p;
		while ((q = strchr(bp, ';'))) {
			*q++ = 0;
			if (q) {
				if (!strncmp(q, "RFC5424", 7))
					f->f_flags |= RFC5424;
				/* More flags can be added here */
			}
			bp = q;
		}
		(void)strcpy(f->f_un.f_forw.f_hname, ++p);
		logit("forwarding host: %s\n", p); /*ASP*/
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = family;
		hints.ai_socktype = SOCK_DGRAM;
		if (getaddrinfo(p, "syslog", &hints, &ai)) {
			/*
			 * The host might be unknown due to an
			 * inaccessible nameserver (perhaps on the
			 * same host). We try to get the ip number
			 * later, like FORW_SUSP.
			 */
			f->f_type = F_FORW_UNKN;
			f->f_prevcount = INET_RETRY_MAX;
			f->f_time = time(NULL);
			f->f_un.f_forw.f_addr = NULL;
		} else {
			f->f_type = F_FORW;
			f->f_un.f_forw.f_addr = ai;
		}
		break;

	case '|':
	case '/':
		/* Look for optional per-file rotate BYTES:COUNT */
		for (q = p; *q && !isspace(*q); q++)
			;
		if (isspace(*q)) {
			char *c;
			int sz = 0, cnt = 0;

			*q++ = 0;
			while (*q && isspace(*q))
				q++;

			c = strchr(q, ':');
			if (c) {
				*c++ = 0;
				cnt = atoi(c);
			}

			sz = strtobytes(q);
			if (sz > 0 && cnt > 0) {
				f->f_rotatecount = cnt;
				f->f_rotatesz = sz;
			}
		}

		(void)strcpy(f->f_un.f_fname, p);
		logit("filename: %s\n", p); /*ASP*/
		if (syncfile)
			f->f_flags |= SYNC_FILE;
		if (*p == '|') {
			f->f_file = open(++p, O_RDWR | O_NONBLOCK | O_NOCTTY);
			f->f_type = F_PIPE;
		} else {
			f->f_file = open(p, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_NOCTTY,
			                 0644);
			f->f_type = F_FILE;
		}

		if (f->f_file < 0) {
			f->f_file = -1;
			logit("Error opening log file: %s\n", p);
			logerror(p);
			break;
		}
		if (isatty(f->f_file)) {
			f->f_type = F_TTY;
			untty();
		}
		if (strcmp(p, ctty) == 0)
			f->f_type = F_CONSOLE;
		break;

	case '*':
		logit("write-all\n");
		f->f_type = F_WALL;
		break;

	default:
		logit("users: %s\n", p); /* ASP */
		for (i = 0; i < MAXUNAMES && *p; i++) {
			for (q = p; *q && *q != ',';)
				q++;
			(void)strncpy(f->f_un.f_uname[i], p, UNAMESZ);
			if ((q - p) > UNAMESZ)
				f->f_un.f_uname[i][UNAMESZ] = '\0';
			else
				f->f_un.f_uname[i][q - p] = '\0';
			while (*q == ',' || *q == ' ')
				q++;
			p = q;
		}
		f->f_type = F_USERS;
		break;
	}
}

/*
 *  Decode a symbolic name to a numeric value
 */
int decode(char *name, struct code *codetab)
{
	struct code *c;
	char *       p;
	char         buf[80];

	logit("symbolic name: %s", name);
	if (isdigit(*name)) {
		logit("\n");
		return atoi(name);
	}
	(void)strncpy(buf, name, 79);
	for (p = buf; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);
	for (c = codetab; c->c_name; c++)
		if (!strcmp(buf, c->c_name)) {
			logit(" ==> %d\n", c->c_val);
			return c->c_val;
		}
	return -1;
}

static void logit(char *fmt, ...)
{
	va_list ap;

	if (!(Debug && debugging_on))
		return;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	fflush(stdout);
}

/*
 * The following function is resposible for handling a SIGHUP signal.  Since
 * we are now doing mallocs/free as part of init we had better not being
 * doing this during a signal handler.  Instead this function simply sets
 * a flag variable which will tell the main loop to go through a restart.
 */
void sighup_handler(int signo)
{
	restart = 1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
