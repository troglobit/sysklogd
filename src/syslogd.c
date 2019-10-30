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

#include "config.h"

#include <assert.h>
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
#include <paths.h>

#include "pidfile.h"
#include "syslogd.h"
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

/*
 * Flags to logmsg().
 */

#define IGN_CONS  0x001  /* don't print on console */
#define SYNC_FILE 0x002  /* do fsync on file after printing */
#define ADDDATE   0x004  /* add a date to the message */
#define MARK      0x008  /* this message is a mark */
#define RFC5424   0x010  /* format log message according to RFC 5424 */

/*
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
static int repeatinterval[] = { 30, 120, 600 };	/* # of secs before flush */
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

static int	  Debug;		/* debug flag */
static int	  Foreground = 0;	/* don't fork - don't run in daemon mode */
static char	  LocalHostName[MAXHOSTNAMELEN + 1]; /* our hostname */
static char	 *LocalDomain;			     /* our local domain name */
static char	 *emptystring = "";
static int	  InetInuse = 0;	  /* non-zero if INET sockets are being used */
static int	 *finet = NULL;		  /* Internet datagram sockets */
static int	  Initialized = 0;	  /* set when we have initialized ourselves */
static int	  MarkInterval = 20 * 60; /* interval between marks in seconds */
static int	  family = PF_UNSPEC;	  /* protocol family (IPv4, IPv6 or both) */
static char      *service = "syslog";	  /* Port to bind to, default 514/udp */
static int	  mask_C1 = 1;		  /* mask characters from 0x80 - 0x9F */
static int	  send_to_all;		  /* send message to all IPv4/IPv6 addresses */
static int	  MarkSeq = 0;		  /* mark sequence number */

static int	  RemoteAddDate;	  /* Always set the date on remote messages */
static int	  RemoteHostname;	  /* Log remote hostname from the message */

static int	  KeepKernFac;		  /* Keep remotely logged kernel facility */

static int	  LastAlarm = 0;	  /* last value passed to alarm() (seconds)  */
static int	  DupesPending = 0;	  /* Number of unflushed duplicate messages */
static int	  AcceptRemote = 0;	  /* receive messages that come via UDP */
static char	**StripDomains = NULL;	  /* these domains may be stripped before writing logs */
static char	**LocalHosts = NULL;	  /* these hosts are logged with their hostname */
static int	  NoHops = 1;		  /* Can we bounce syslog messages through an intermediate host. */
static off_t	  RotateSz = 0;		  /* Max file size (bytes) before rotating, disabled by default */
static int	  RotateCnt = 5;	  /* Max number (count) of log files to keep, set with -c <NUM> */

/* Function prototypes. */
char      **crunch_list(char *list);
int         usage(int code);
void        untty(void);
static void parsemsg(const char *from, char *msg);
void        printsys(char *msg);
static void logmsg(struct buf_msg *buffer);
static void fprintlog(struct filed *f, struct buf_msg *buffer);
void        endtty();
void        wallmsg(struct filed *f, struct iovec *iov, int iovcnt);
void        reapchild();
const char *cvtaddr(struct sockaddr_storage *f, int len);
const char *cvthname(struct sockaddr_storage *f, int len);
static void flog(int pri, char *fmt, ...);
void        domark();
void        debug_switch();
void        logerror(const char *type);
void        die(int sig);
void        doexit(int sig);
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
	struct sockaddr_storage frominet;
	pid_t ppid = getpid();
	socklen_t len;
	ssize_t msglen;
	int fd;
	fd_set readfds;
	char line[MAXLINE + 1];
	char *ptr;
	int num_fds, maxfds;
	int i, ch;

	for (i = 1; i < MAXFUNIX; i++) {
		funixn[i] = "";
		funix[i] = -1;
	}

	while ((ch = getopt(argc, argv, "46Aa:b:dhHf:l:m:nP:p:R:rs:v?")) != EOF) {
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

		case 'b':
			ptr = strchr(optarg, ':');
			if (ptr)
				service = ++ptr;
			break;

		case 'd': /* debug */
			Debug = 1;
			break;

		case 'f': /* configuration file */
			ConfFile = optarg;
			break;

		case 'H':
			RemoteHostname = 1;
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

		case 'P':
			PidFile = optarg;
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
	} else {
		debugging_on = 1;
		setlinebuf(stdout);
	}

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
	}

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
		if (getpid() != ppid)
			kill(ppid, SIGTERM);
		die(0);
	}
	for (i = 0; i < num_fds; ++i)
		parts[i] = NULL;

	logit("Starting.\n");
	init();

	if (Debug) {
		logit("Debugging disabled, SIGUSR1 to turn on debugging.\n");
		debugging_on = 0;
	}

	/*
	 * Send a signal to the parent to it can terminate.
	 */
	if (getpid() != ppid)
		kill(ppid, SIGTERM);

	/* Main loop begins here. */
	for (;;) {
		int nfds;

		errno = 0;
		FD_ZERO(&readfds);
		maxfds = 0;

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

			if (check_pid(PidFile)) {
				if (touch_pid(PidFile))
					logerror("Not possible to touch pidfile");
			} else {
				if (!write_pid(PidFile))
					logerror("Failed to write pidfile");
			}
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

		for (i = 0; i < nfunix; i++) {
			if ((fd = funix[i]) != -1 && FD_ISSET(fd, &readfds)) {
				memset(line, 0, sizeof(line));
				msglen = recv(fd, line, MAXLINE - 2, 0);
				logit("Message from UNIX socket: #%d\n", fd);
				if (msglen > 0)
					parsemsg(LocalHostName, line);
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
							parsemsg(from, line);
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
	}
}

int usage(int code)
{
	fprintf(stdout,
	        "Usage:\n"
	        "  syslogd [-46Adnrvh?] [-a SOCK] [-f FILE] [-l HOST] [-m SEC] [-P PID_FILE]\n"
	        "                       [-p SOCK_PATH] [-R SIZE[:NUM]] [-s NAME[:NAME[...]]]\n"
	        "\n"
	        "Options:\n"
	        "  -4        Force IPv4 only\n"
	        "  -6        Force IPv6 only\n"
	        "  -A        Send to all addresses in DNS A, or AAAA record\n"
	        "  -a SOCK   Additional socket (max 19) to listen to, used with chroots\n"
	        "  -d        Enable debug mode\n"
	        "  -f FILE   Alternate .conf file, default: /etc/syslog.conf\n"
	        "  -h        Forward messages from other hosts also to remote syslog host(s)\n"
	        "  -l HOST   Host name to log without its FQDN, use ':' for multiple hosts\n"
	        "  -m SEC    Interval between MARK messages in log, 0 to disable, default: 20\n"
	        "  -n        Run in foreground, required when run from a modern init/supervisor\n"
		"  -P FILE   Specify an	alternative file in which to store the process ID.\n"
		"            The default is %s.\n"
	        "  -p PATH   Alternate path to UNIX domain socket, default: %s\n"
		"  -R S[:R]  Enable log rotation.  The size argument (S) takes k/M/G qualifiers,\n"
		"            e.g. 2M for 2 MiB.  The optional rotations argument default to 5.\n"
		"            Rotation can also be defined per log file in syslog.conf\n"
	        "  -r        Act as remote syslog sink for other hosts\n"
	        "  -s NAME   Strip domain name before logging, use ':' for multiple domains\n"
		"\n"
	        "  -?        Show this help text\n"
	        "  -v        Show program version and exit\n"
	        "\n"
	        "Bug report address: %s\n",
		_PATH_LOGPID, _PATH_LOG, PACKAGE_BUGREPORT);
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
	error = getaddrinfo(NULL, service, &hints, &res);
	if (error) {
		flog(LOG_SYSLOG | LOG_ERR, "network logging disabled (%s/udp "
		     " service unknown): %s", service, gai_strerror(error));
		logerror("see syslogd(8) for details of whether and how to enable it.");
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

		logit("Created inet socket %d ...\n", *s);
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
 * Removes characters from log messages that are unsafe to display.
 * TODO: Permit UTF-8 strings that include a BOM per RFC 5424?
 */
static void
parsemsg_remove_unsafe_characters(const char *in, char *out, size_t outlen)
{
	char *q;
	int c;

	q = out;
	while ((c = (unsigned char)*in++) != '\0' && q < out + outlen - 4) {
		if (mask_C1 && (c & 0x80) && c < 0xA0) {
			c &= 0x7F;
			*q++ = 'M';
			*q++ = '-';
		}
		if (isascii(c) && iscntrl(c)) {
			if (c == '\n') {
				*q++ = ' ';
			} else if (c == '\t') {
				*q++ = '\t';
			} else {
				*q++ = '^';
				*q++ = c ^ 0100;
			}
		} else {
			*q++ = c;
		}
	}
	*q = '\0';
}

/*
 * Parses a syslog message according to RFC 5424, assuming that PRI and
 * VERSION (i.e., "<%d>1 ") have already been parsed by parsemsg(). The
 * parsed result is passed to logmsg().
 */
static void
parsemsg_rfc5424(const char *from, int pri, char *msg)
{
	const struct logtime *timestamp = NULL;
	struct logtime timestamp_remote;
	struct buf_msg buffer;
	const char *omsg;
	char line[MAXLINE + 1];

	memset(&buffer, 0, sizeof(buffer));
	buffer.recvhost = (char *)from;
	buffer.pri = pri;
	buffer.msg = line;

#define	FAIL_IF(field, expr) do {					\
	if (expr) {							\
		logit("Failed to parse " field " from %s: %s\n",	\
		      from, omsg);					\
		return;							\
	}								\
} while (0)
#define	PARSE_CHAR(field, sep) do {					\
	FAIL_IF(field, *msg != sep);					\
	++msg;								\
} while (0)
#define	IF_NOT_NILVALUE(var)						\
	if (msg[0] == '-' && msg[1] == ' ') {				\
		msg += 2;						\
		var = NULL;						\
	} else if (msg[0] == '-' && msg[1] == '\0') {			\
		++msg;							\
		var = NULL;						\
	} else

	omsg = msg;
	IF_NOT_NILVALUE(timestamp) {
		/* Parse RFC 3339-like timestamp. */
#define	PARSE_NUMBER(dest, length, min, max) do {			\
	int i, v;							\
									\
	v = 0;								\
	for (i = 0; i < length; ++i) {					\
		FAIL_IF("TIMESTAMP", *msg < '0' || *msg > '9');		\
		v = v * 10 + *msg++ - '0';				\
	}								\
	FAIL_IF("TIMESTAMP", v < min || v > max);			\
	dest = v;							\
} while (0)
		/* Date and time. */
		memset(&timestamp_remote, 0, sizeof(timestamp_remote));
		PARSE_NUMBER(timestamp_remote.tm.tm_year, 4, 0, 9999);
		timestamp_remote.tm.tm_year -= 1900;
		PARSE_CHAR("TIMESTAMP", '-');
		PARSE_NUMBER(timestamp_remote.tm.tm_mon, 2, 1, 12);
		--timestamp_remote.tm.tm_mon;
		PARSE_CHAR("TIMESTAMP", '-');
		PARSE_NUMBER(timestamp_remote.tm.tm_mday, 2, 1, 31);
		PARSE_CHAR("TIMESTAMP", 'T');
		PARSE_NUMBER(timestamp_remote.tm.tm_hour, 2, 0, 23);
		PARSE_CHAR("TIMESTAMP", ':');
		PARSE_NUMBER(timestamp_remote.tm.tm_min, 2, 0, 59);
		PARSE_CHAR("TIMESTAMP", ':');
		PARSE_NUMBER(timestamp_remote.tm.tm_sec, 2, 0, 59);
		/* Perform normalization. */
		timegm(&timestamp_remote.tm);
		/* Optional: fractional seconds. */
		if (msg[0] == '.' && msg[1] >= '0' && msg[1] <= '9') {
			int i;

			++msg;
			for (i = 100000; i != 0; i /= 10) {
				if (*msg < '0' || *msg > '9')
					break;
				timestamp_remote.usec += (*msg++ - '0') * i;
			}
		}
		/* Timezone. */
		if (*msg == 'Z') {
			/* UTC. */
			++msg;
		} else {
			int sign, tz_hour, tz_min;

			/* Local time zone offset. */
			FAIL_IF("TIMESTAMP", *msg != '-' && *msg != '+');
			sign = *msg++ == '-' ? -1 : 1;
			PARSE_NUMBER(tz_hour, 2, 0, 23);
			PARSE_CHAR("TIMESTAMP", ':');
			PARSE_NUMBER(tz_min, 2, 0, 59);
			timestamp_remote.tm.tm_gmtoff =
			    sign * (tz_hour * 3600 + tz_min * 60);
		}
#undef PARSE_NUMBER
		PARSE_CHAR("TIMESTAMP", ' ');
		if (!RemoteAddDate)
			timestamp = &timestamp_remote;
	}

	if (timestamp)
		buffer.timestamp = *timestamp;

	/* String fields part of the HEADER. */
#define	PARSE_STRING(field, var)					\
	IF_NOT_NILVALUE(var) {						\
		var = msg;						\
		while (*msg >= '!' && *msg <= '~')			\
			++msg;						\
		FAIL_IF(field, var == msg);				\
		PARSE_CHAR(field, ' ');					\
		msg[-1] = '\0';						\
	}
	PARSE_STRING("HOSTNAME", buffer.hostname);
	if (buffer.hostname == NULL || !RemoteHostname)
		buffer.hostname = (char *)from;
	PARSE_STRING("APP-NAME", buffer.app_name);
	PARSE_STRING("PROCID", buffer.proc_id);
	PARSE_STRING("MSGID", buffer.msgid);
#undef PARSE_STRING

	/* Structured data. */
#define	PARSE_SD_NAME() do {						\
	const char *start;						\
									\
	start = msg;							\
	while (*msg >= '!' && *msg <= '~' && *msg != '=' &&		\
	    *msg != ']' && *msg != '"')					\
		++msg;							\
	FAIL_IF("STRUCTURED-NAME", start == msg);			\
} while (0)
	IF_NOT_NILVALUE(buffer.sd) {
		/* SD-ELEMENT. */
		while (*msg == '[') {
			++msg;
			/* SD-ID. */
			PARSE_SD_NAME();
			/* SD-PARAM. */
			while (*msg == ' ') {
				++msg;
				/* PARAM-NAME. */
				PARSE_SD_NAME();
				PARSE_CHAR("STRUCTURED-NAME", '=');
				PARSE_CHAR("STRUCTURED-NAME", '"');
				while (*msg != '"') {
					FAIL_IF("STRUCTURED-NAME",
					    *msg == '\0');
					if (*msg++ == '\\') {
						FAIL_IF("STRUCTURED-NAME",
						    *msg == '\0');
						++msg;
					}
				}
				++msg;
			}
			PARSE_CHAR("STRUCTURED-NAME", ']');
		}
		PARSE_CHAR("STRUCTURED-NAME", ' ');
		msg[-1] = '\0';
	}
#undef PARSE_SD_NAME

#undef FAIL_IF
#undef PARSE_CHAR
#undef IF_NOT_NILVALUE
	parsemsg_remove_unsafe_characters(msg, line, sizeof(line));
	buffer.msg = line;

	logmsg(&buffer);
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
	    "_-");
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
 * Parses a syslog message according to RFC 3164, assuming that PRI
 * (i.e., "<%d>") has already been parsed by parsemsg(). The parsed
 * result is passed to logmsg().
 */
static void
parsemsg_rfc3164(const char *from, int pri, char *msg)
{
	struct logtime timestamp_remote;
	struct buf_msg buffer;
	struct tm tm_parsed;
	size_t i, msglen;
	char line[MAXLINE + 1];

	memset(&buffer, 0, sizeof(buffer));
	buffer.recvhost = (char *)from;
	buffer.msg = line;

	/* Parse the timestamp provided by the remote side. */
	if (strptime(msg, RFC3164_DATEFMT, &tm_parsed) !=
	    msg + RFC3164_DATELEN || msg[RFC3164_DATELEN] != ' ') {
		logit("Failed to parse TIMESTAMP from %s: %s\n", from, msg);
		return;
	}
	msg += RFC3164_DATELEN + 1;

	if (!RemoteAddDate) {
		struct tm tm_now;
		time_t t_now;
		int year;

		/*
		 * As the timestamp does not contain the year number,
		 * daylight saving time information, nor a time zone,
		 * attempt to infer it. Due to clock skews, the
		 * timestamp may even be part of the next year. Use the
		 * last year for which the timestamp is at most one week
		 * in the future.
		 *
		 * This loop can only run for at most three iterations
		 * before terminating.
		 */
		t_now = time(NULL);
		localtime_r(&t_now, &tm_now);
		for (year = tm_now.tm_year + 1;; --year) {
			assert(year >= tm_now.tm_year - 1);
			timestamp_remote.tm = tm_parsed;
			timestamp_remote.tm.tm_year = year;
			timestamp_remote.tm.tm_isdst = -1;
			timestamp_remote.usec = 0;
			if (mktime(&timestamp_remote.tm) <
			    t_now + 7 * 24 * 60 * 60)
				break;
		}
		buffer.timestamp = timestamp_remote;
	}

	/*
	 * A single space character MUST also follow the HOSTNAME field.
	 */
	msglen = strlen(msg);
	for (i = 0; i < MIN(MAXHOSTNAMELEN, msglen); i++) {
		if (msg[i] == ' ') {
			if (RemoteHostname) {
				msg[i] = '\0';
				buffer.hostname = msg;
			}
			msg += i + 1;
			break;
		}
		/*
		 * Support non RFC compliant messages, without hostname.
		 */
		if (msg[i] == ':')
			break;
	}

	if (i == MIN(MAXHOSTNAMELEN, msglen)) {
		logit("Invalid HOSTNAME from %s: %s\n", from, msg);
		return;
	}

	/* Remove the TAG, if present. */
	parsemsg_rfc3164_app_name_procid(&msg, &buffer.app_name, &buffer.proc_id);
	parsemsg_remove_unsafe_characters(msg, line, sizeof(line));
	logmsg(&buffer);
}

/*
 * Takes a raw input line, extracts PRI and determines whether the
 * message is formatted according to RFC 3164 or RFC 5424. Continues
 * parsing of addition fields in the message according to those
 * standards and prints the message on the appropriate log files.
 */
static void
parsemsg(const char *from, char *msg)
{
	char *q;
	long n;
	size_t i;
	int pri;

	/* Parse PRI. */
	if (msg[0] != '<' || !isdigit(msg[1])) {
		logit("Invalid PRI from %s\n", from);
		return;
	}
	for (i = 2; i <= 4; i++) {
		if (msg[i] == '>')
			break;
		if (!isdigit(msg[i])) {
			logit("Invalid PRI header from %s\n", from);
			return;
		}
	}
	if (msg[i] != '>') {
		logit("Invalid PRI header from %s\n", from);
		return;
	}
	errno = 0;
	n = strtol(msg + 1, &q, 10);
	if (errno != 0 || *q != msg[i] || n < 0 || n >= INT_MAX) {
		logit("Invalid PRI %ld from %s: %s\n",
		      n, from, strerror(errno));
		return;
	}
	pri = n;
	if (pri &~ (LOG_FACMASK|LOG_PRIMASK))
		pri = DEFUPRI;

	/*
	 * Don't allow users to log kernel messages.
	 * NOTE: since LOG_KERN == 0 this will also match
	 *       messages with no facility specified.
	 */
	if ((pri & LOG_FACMASK) == LOG_KERN && !KeepKernFac)
		pri = LOG_MAKEPRI(LOG_USER, LOG_PRI(pri));

	/* Parse VERSION. */
	msg += i + 1;
	if (msg[0] == '1' && msg[1] == ' ')
		parsemsg_rfc5424(from, pri, msg + 2);
	else
		parsemsg_rfc3164(from, pri, msg);
}

/*
 * Take a raw input line from /dev/klog, split and format similar to syslog().
 */
void printsys(char *msg)
{
	struct buf_msg buffer;
	char line[MAXLINE + 1];
	char *lp, *p, *q;
	int c;

	lp = line;
	for (p = msg; *p != '\0';) {
		memset(&buffer, 0, sizeof(buffer));
		buffer.app_name = "vmunix";
		buffer.pri = DEFSPRI;
		buffer.msg = line;

		if (*p == '<') {
			buffer.pri = 0;
			while (isdigit(*++p))
				buffer.pri = 10 * buffer.pri + (*p - '0');
			if (*p == '>')
				++p;
		} else {
			/* kernel printf's come out on console */
			buffer.flags |= IGN_CONS;
		}

		if (buffer.pri & ~(LOG_FACMASK | LOG_PRIMASK))
			buffer.pri = DEFSPRI;

		q = lp;
		while (*p != '\0' && (c = *p++) != '\n' && q < &line[MAXLINE])
			*q++ = c;
		*q = '\0';

		logmsg(&buffer);
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
 * Logs a message to the appropriate log files, users, etc. based on the
 * priority. Log messages are always formatted according to RFC 3164,
 * even if they were in RFC 5424 format originally, The MSGID and
 * STRUCTURED-DATA fields are thus discarded for the time being.
 */
static void logmsg(struct buf_msg *buffer)
{
	struct logtime timestamp_now;
	struct logtime zero = { 0 };
	struct timeval tv;
	struct filed *f;
	sigset_t mask;
	size_t savedlen;
	char saved[MAXSVLINE];
	int fac, prilev;

	logit("logmsg: %s, flags %x, from %s, msg %s\n", textpri(buffer->pri),
	      buffer->flags, buffer->hostname, buffer->msg);

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGALRM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	(void)gettimeofday(&tv, NULL);
	now = tv.tv_sec;
	if (!memcmp(&buffer->timestamp, &zero, sizeof(zero))) {
		localtime_r(&now, &timestamp_now.tm);
		timestamp_now.usec = tv.tv_usec;
		buffer->timestamp = timestamp_now;
	}

	/* extract facility and priority level */
	if (buffer->flags & MARK)
		fac = LOG_NFACILITIES;
	else
		fac = LOG_FAC(buffer->pri);

	/* Check maximum facility number. */
	if (fac > LOG_NFACILITIES)
		return;

	prilev = LOG_PRI(buffer->pri);

	/* log the message to the particular outputs */
	if (!Initialized) {
		f = &consfile;
		f->f_file = open(ctty, O_WRONLY | O_NOCTTY);

		if (f->f_file >= 0) {
			untty();
			fprintlog(f, buffer);
			(void)close(f->f_file);
			f->f_file = -1;
		}

		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		return;
	}

	/*
	 * Store all of the fields of the message, except the timestamp,
	 * in a single string. This string is used to detect duplicate
	 * messages.
	 */
	assert(buffer->hostname != NULL);
	assert(buffer->msg != NULL);
	savedlen = snprintf(saved, sizeof(saved),
			    "%d %s %s %s %s %s %s", buffer->pri, buffer->hostname,
			    buffer->app_name == NULL ? "-" : buffer->app_name,
			    buffer->proc_id == NULL ? "-" : buffer->proc_id,
			    buffer->msgid == NULL ? "-" : buffer->msgid,
			    buffer->sd == NULL ? "-" : buffer->sd, buffer->msg);

	for (f = Files; f; f = f->f_next) {
		/* skip messages that are incorrect priority */
		if ((f->f_pmask[fac] == TABLE_NOPRI) ||
		    ((f->f_pmask[fac] & (1 << prilev)) == 0))
			continue;

		/* skip message to console if it has already been printed */
		if (f->f_type == F_CONSOLE && (buffer->flags & IGN_CONS))
			continue;

		/* don't output marks to recently written files */
		if ((buffer->flags & MARK) && (now - f->f_time) < MarkInterval / 2)
			continue;

		/*
		 * suppress duplicate lines to this file
		 */
		if ((buffer->flags & MARK) == 0 && savedlen == f->f_prevlen &&
		    !strcmp(saved, f->f_prevline)) {
			f->f_lasttime = buffer->timestamp;
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
				fprintlog(f, NULL);
				BACKOFF(f);
			}
		} else {
			/* new line, save it */
			if (f->f_prevcount) {
				fprintlog(f, NULL);

				if (--DupesPending == 0) {
					logit("unsetting duplicate message flush alarm\n");

					MarkSeq += LastAlarm - alarm(0);
					LastAlarm = MarkInterval - MarkSeq;
					alarm(LastAlarm);
				}
			}
			f->f_prevpri = buffer->pri;
			f->f_repeatcount = 0;
			f->f_lasttime = buffer->timestamp;
			(void)strncpy(f->f_prevhost, buffer->hostname,
			              sizeof(f->f_prevhost));
			(void)strcpy(f->f_prevline, saved);
			f->f_prevlen = savedlen;
			fprintlog(f, buffer);
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

#define pushiov(iov, cnt, val) do {		\
		iov[cnt].iov_base = val;	\
		iov[cnt].iov_len = strlen(val);	\
		cnt++;				\
	} while (0);

#define pushsp(iov, cnt) do {			\
		iov[cnt].iov_base = " ";	\
		iov[cnt].iov_len = 1;		\
		cnt++;				\
	} while (0);

#define fmtlogit(bm) logit("%s(%d, 0x%02x, %s, %s, %s, %s, %s, %s)", __func__, \
			   bm->pri, bm->flags, bm->hostname, bm->app_name,     \
			   bm->proc_id, bm->msgid, bm->sd, bm->msg)

static int fmt3164(struct buf_msg *buffer, struct iovec *iov, size_t iovmax)
{
	int i = 0;

	fmtlogit(buffer);
	strftime(buffer->timebuf, sizeof(buffer->timebuf), RFC3164_DATEFMT,
		 &buffer->timestamp.tm);

	snprintf(buffer->pribuf, sizeof(buffer->pribuf), "<%d>", buffer->pri);
	pushiov(iov, i, buffer->pribuf);
	pushsp(iov, i);

	pushiov(iov, i, buffer->timebuf);
	pushsp(iov, i);

	pushiov(iov, i, buffer->hostname ? buffer->hostname : buffer->recvhost);
	pushsp(iov, i);

	if (buffer->app_name) {
		pushiov(iov, i, buffer->app_name);
		if (buffer->proc_id) {
			pushiov(iov, i, "[");
			pushiov(iov, i, buffer->proc_id);
			pushiov(iov, i, "]:");
		}
		pushsp(iov, i);
	}

	pushiov(iov, i, buffer->msg);

	return i;
}

static int fmt5424(struct buf_msg *buffer, struct iovec *iov, size_t iovmax)
{
	suseconds_t usec;
	int i = 0;

	fmtlogit(buffer);
	strftime(buffer->timebuf, sizeof(buffer->timebuf), "%FT%T.______%z",
		 &buffer->timestamp.tm);

	/* Add colon to the time zone offset, which %z doesn't do */
	buffer->timebuf[32] = '\0';
	buffer->timebuf[31] = buffer->timebuf[30];
	buffer->timebuf[30] = buffer->timebuf[29];
	buffer->timebuf[29] = ':';

	/* Overwrite space for microseconds with actual value */
	usec = buffer->timestamp.usec;
	for (int i = 25; i >= 20; --i) {
		buffer->timebuf[i] = usec % 10 + '0';
		usec /= 10;
	}

	/* RFC 5424 defines itself as v1 */
	snprintf(buffer->pribuf, sizeof(buffer->pribuf), "<%d>1", buffer->pri);
	pushiov(iov, i, buffer->pribuf);
	pushsp(iov, i);

	pushiov(iov, i, buffer->timebuf);
	pushsp(iov, i);

	pushiov(iov, i, buffer->hostname ? buffer->hostname : buffer->recvhost);
	pushsp(iov, i);

	pushiov(iov, i, buffer->app_name ? buffer->app_name : "-");
	pushsp(iov, i);

	pushiov(iov, i, buffer->proc_id ? buffer->proc_id : "-");
	pushsp(iov, i);

	pushiov(iov, i, buffer->msgid ? buffer->msgid : "-");
	pushsp(iov, i);

	pushiov(iov, i, buffer->sd ? buffer->sd : "-");
	pushsp(iov, i);

	pushiov(iov, i, buffer->msg);

	return i;
}

void fprintlog(struct filed *f, struct buf_msg *buffer)
{
	struct addrinfo hints, *ai;
	struct buf_msg repeat;
	struct logtime zero = { 0 };
	struct iovec iov[20];
	time_t fwd_suspend;
	char repbuf[80];
	char line[MAXLINE + 1];
	int iovhead = 1;
	int iovcnt = iovhead; /* One to spare at head for remote <PRI> */
	int err;

	logit("Called fprintlog, ");
	if (!buffer) {
		memset(&repeat, 0, sizeof(repeat));
		repeat.hostname = f->f_prevhost;
		repeat.pri = f->f_prevpri;
		repeat.timestamp = f->f_lasttime;
		if (f->f_prevcount > 1) {
			snprintf(repbuf, sizeof(repbuf),
				 "last message repeated %d times",
				 f->f_prevcount);
			repeat.msg = repbuf;
		} else {
			strlcpy(line, f->f_prevline, sizeof(line));
			repeat.msg = line;
		}

		buffer = &repeat;
	}

	if (!memcmp(&buffer->timestamp, &zero, sizeof(zero))) {
		struct logtime timestamp_now;
		struct timeval tv;

		(void)gettimeofday(&tv, NULL);
		now = tv.tv_sec;

		localtime_r(&now, &timestamp_now.tm);
		timestamp_now.usec = tv.tv_usec;
		buffer->timestamp = timestamp_now;
	}

	if (f->f_flags & RFC5424)
		iovcnt = fmt5424(buffer, iov, NELEMS(iov));
	else
		iovcnt = fmt3164(buffer, iov, NELEMS(iov));

	/* Save actual message for future repeats */
//	if (iovcnt > 0)
//		strlcpy(f->f_prevline, iov[iovcnt - 1].iov_base, sizeof(f->f_prevline));

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
			char *host;

			logit("Forwarding suspension to unknown over, retrying\n");
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = family;
			hints.ai_socktype = SOCK_DGRAM;
			host = f->f_un.f_forw.f_hname;
			err = getaddrinfo(host, service, &hints, &ai);
			if (err) {
				logit("Failure resolving %s:%s: %s\n", host, service, gai_strerror(err));
				logit("Retries: %d\n", f->f_prevcount);
				if (--f->f_prevcount < 0) {
					logit("Giving up.\n");
					f->f_type = F_UNUSED;
				} else
					logit("Left retries: %d\n", f->f_prevcount);
			} else {
				logit("%s found, resuming.\n", host);
				f->f_un.f_forw.f_addr = ai;
				f->f_prevcount = 0;
				f->f_type = F_FORW;
				goto f_forw;
			}
		} else
			logit("Forwarding suspension not over, time left: %d\n",
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
		if (strcmp(buffer->hostname, LocalHostName) && NoHops)
			logit("Not sending message to remote.\n");
		else if (finet) {
			struct msghdr msg;
			ssize_t len = 0;

			f->f_time = now;

			memset(&msg, 0, sizeof(msg));
			msg.msg_iov = iov;
			msg.msg_iovlen = iovcnt;

			for (int i = 0; i < iovcnt; i++) {
				logit("iov[%d] => %s\n", i, iov[i].iov_base);
				len += iov[i].iov_len;
			}

			err = -1;
			for (ai = f->f_un.f_forw.f_addr; ai; ai = ai->ai_next) {
				for (int i = 0; i < *finet; i++) {
					struct sockaddr_in *sin;
					char buf[64] = { 0 };
					ssize_t lsent;

					msg.msg_name = ai->ai_addr;
					msg.msg_namelen = ai->ai_addrlen;
					lsent = sendmsg(finet[i + 1], &msg, 0);

					if (AF_INET == ai->ai_family) {
						sin = (struct sockaddr_in *)ai->ai_addr;
						inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
					}
					logit("Sent %d bytes to remote %s on socket %d ...\n",
					      lsent, buf, finet[i + 1]);
					if (lsent == len) {
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
		if (buffer->flags & IGN_CONS) {
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
			pushiov(iov, iovcnt, "\r\n");
		} else {
			pushiov(iov, iovcnt, "\n");
		}
	again:
		/* f->f_file == -1 is an indicator that we couldn't
		   open the file at startup. */
		if (f->f_file == -1)
			break;

		if (f->f_type == F_FILE)
			logrotate(f);

		if (writev(f->f_file, &iov[2], iovcnt - 2) < 0) {
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
		pushiov(iov, iovcnt, "\r\n");
		wallmsg(f, &iov[2], iovcnt - 2);
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
void wallmsg(struct filed *f, struct iovec *iov, int iovcnt)
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
						(void)writev(ttyf, iov, iovcnt);
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

/*
 * Base function for domark(), logerror(), etc.
 */
static void flog(int pri, char *fmt, ...)
{
	struct buf_msg buffer;
	va_list ap;
	char proc_id[10];
	char buf[BUFSIZ];

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	(void)snprintf(proc_id, sizeof(proc_id), "%d", getpid());

	memset(&buffer, 0, sizeof(buffer));
	buffer.hostname = LocalHostName;
	buffer.app_name = "syslogd";
	buffer.proc_id  = proc_id;
	buffer.pri = pri;
	buffer.msg = buf;
	if (pri & LOG_MARK)
		buffer.flags = MARK;

	logmsg(&buffer);
}

void domark(int signo)
{
	struct filed *f;

	if (MarkInterval > 0) {
		now = time(0);
		MarkSeq += LastAlarm;
		if (MarkSeq >= MarkInterval) {
			flog(LOG_MARK | LOG_INFO, "-- MARK --");
			MarkSeq -= MarkInterval;
		}
	}

	for (f = Files; f; f = f->f_next) {
		if (f->f_prevcount && now >= REPEATTIME(f)) {
			logit("flush %s: repeated %d times, %d sec.\n",
			      TypeNames[f->f_type], f->f_prevcount,
			      repeatinterval[f->f_repeatcount]);
			fprintlog(f, NULL);
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
	logit("Called logerr, msg: %s\n", type);

	if (errno == 0)
		flog(LOG_SYSLOG | LOG_ERR, "%s", type);
	else
		flog(LOG_SYSLOG | LOG_ERR, "%s: %m", type);
}

void die(int signo)
{
	struct filed *f;
	int lognum;
	int i;
	int was_initialized = Initialized;

	Initialized = 0; /* Don't log SIGCHLDs in case we
			    receive one during exiting */

	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog(f, NULL);
	}

	Initialized = was_initialized;
	if (signo) {
		logit("syslogd: exiting on signal %d\n", signo);
		flog(LOG_SYSLOG | LOG_INFO, "exiting on signal %d", signo);
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

	(void)remove_pid(PidFile);
	exit(0);
}

/*
 * Signal handler to terminate the parent process.
 */
void doexit(int signo)
{
	exit(0);
}

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
				fprintlog(f, NULL);

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

		cfline("*.err\t" _PATH_CONSOLE, f);

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
		flog(LOG_SYSLOG | LOG_INFO, "syslogd v" VERSION ": restart (remote reception).");
	else
		flog(LOG_SYSLOG | LOG_INFO, "syslogd v" VERSION ": restart.");

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
		if (getaddrinfo(p, service, &hints, &ai)) {
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
