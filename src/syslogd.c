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

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <glob.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#include <errno.h>
#include <err.h>
#include <fnmatch.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/sysinfo.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <syscall.h>
#include <paths.h>

#define SYSLOG_NAMES
#include "syslogd.h"
#include "socket.h"
#include "timer.h"
#include "compat.h"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define SecureMode (secure_opt > 0 ? secure_opt : secure_mode)

char *CacheFile = _PATH_CACHE;
char *ConfFile  = _PATH_LOGCONF;
char *PidFile   = _PATH_LOGPID;
char  ctty[]    = _PATH_CONSOLE;

static volatile sig_atomic_t debugging_on;
static volatile sig_atomic_t restart;
static volatile sig_atomic_t rotate_signal;

static const char version_info[] = PACKAGE_NAME " v" PACKAGE_VERSION;

/*
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
static int repeatinterval[] = { 30, 120, 600 };	/* # of secs before flush */

/* values for f_type */
static char *TypeNames[] = {
	"UNUSED",        "FILE",  "TTY",  "CONSOLE",
	"FORW",          "USERS", "WALL", "FORW(SUSPENDED)",
	"FORW(UNKNOWN)", "PIPE"
};

static SIMPLEQ_HEAD(files, filed) fhead = SIMPLEQ_HEAD_INITIALIZER(fhead);
struct filed consfile;

static int	  Debug;		/* debug flag */
static int	  Foreground = 0;	/* don't fork - don't run in daemon mode */
static time_t	  boot_time;		/* Offset for printsys() */
static uint64_t	  sys_seqno = 0;	/* Last seen kernel log message */
static int	  sys_seqno_init;	/* Timestamp can be in the past, use 'now' after first read */
static int	  resolve = 1;		/* resolve hostname */
static char	  LocalHostName[MAXHOSTNAMELEN + 1]; /* our hostname */
static char	 *LocalDomain;			     /* our local domain name */
static char	 *emptystring = "";
static int	  Initialized = 0;	  /* set when we have initialized ourselves */
static int	  MarkInterval = 20 * 60; /* interval between marks in seconds */
static int	  family = PF_UNSPEC;	  /* protocol family (IPv4, IPv6 or both) */
static int	  mask_C1 = 1;		  /* mask characters from 0x80 - 0x9F */
static int	  send_to_all;		  /* send message to all IPv4/IPv6 addresses */
static int	  no_compress;		  /* don't compress messages (1=pipes, 2=all) */
static int	  secure_opt;		  /* sink for others, log to remote, or only unix domain socks */
static int	  secure_mode;		  /* same as above but from syslog.conf, only if cmdline unset */

static int	  RemoteAddDate;	  /* Always set the date on remote messages */
static int	  RemoteHostname;	  /* Log remote hostname from the message */

static int	  KernLog = 1;		  /* Track kernel logs by default */
static int	  KeepKernFac;		  /* Keep remotely logged kernel facility */
static int	  KeepKernTime;		  /* Keep kernel timestamp, evern after initial read */

static off_t	  RotateSz = 0;		  /* Max file size (bytes) before rotating, disabled by default */
static int	  RotateCnt = 5;	  /* Max number (count) of log files to keep, set with -c <NUM> */

/*
 * List of notifiers
 */
static SIMPLEQ_HEAD(notifiers, notifier) nothead = SIMPLEQ_HEAD_INITIALIZER(nothead);

/*
 * List of peers and sockets for binding.
 */
static SIMPLEQ_HEAD(, peer) pqueue = SIMPLEQ_HEAD_INITIALIZER(pqueue);

/*
 * List fo peers allowed to log to us.
 */
static SIMPLEQ_HEAD(, allowedpeer) aphead = SIMPLEQ_HEAD_INITIALIZER(aphead);

/*
 * central list of recognized configuration keywords with an optional
 * address for their values as strings.  If there is no value ptr, the
 * parser moves the argument to the beginning of the parsed line.
 */
char *secure_str;			  /* string value of secure_mode */

const struct cfkey {
	const char  *key;
	char       **var;
} cfkey[] = {
	{ "notify",      NULL        },
	{ "secure_mode", &secure_str },
};

/* Function prototypes. */
static int  allowaddr(char *s);
void        untty(void);
static void parsemsg(const char *from, char *msg);
static int  opensys(const char *file);
static void printsys(char *msg);
static void unix_cb(int sd, void *arg);
static void logmsg(struct buf_msg *buffer);
static void logrotate(struct filed *f);
static void rotate_file(struct filed *f, struct stat *stp_or_null);
static void rotate_all_files(void);
static void fprintlog_first(struct filed *f, struct buf_msg *buffer);
static void fprintlog_successive(struct filed *f, int flags);
void        endtty();
void        wallmsg(struct filed *f, struct iovec *iov, int iovcnt);
void        reapchild();
const char *cvtaddr(struct sockaddr_storage *f, int len);
const char *cvthname(struct sockaddr *f, socklen_t len);
static void forw_lookup(struct filed *f);
void        domark(void *arg);
void        doflush(void *arg);
void        debug_switch();
void        die(int sig);
static void signal_init(void);
static void boot_time_init(void);
static void init(void);
static int  strtobytes(char *arg);
static int  cfparse(FILE *fp, struct files *newf, struct notifiers *newn);
int         decode(char *name, struct _code *codetab);
static void logit(char *, ...);
static void notifier_add(struct notifiers *newn, const char *program);
static void notifier_invoke(const char *logfile);
static void notifier_free_all(void);
void        reload(int);
static void signal_rotate(int sig);
static int  validate(struct sockaddr *sa, const char *hname);
static int  waitdaemon(int);
static void timedout(int);


/*
 * Very basic, and incomplete, check if we're running in a container.
 * If so, we probably want to disable kernel logging.
 */
static int in_container(void)
{
	const char *files[] = {
		"/run/.containerenv",
		"/.dockerenv"
	};
	const char *containers[] = {
		"lxc",
		"docker",
		"kubepod"
	};
	size_t i;
	char *c;

	c = getenv("container");
	if (c) {
		for (i = 0; i < NELEMS(containers); i++) {
			if (!strcmp(containers[i], c))
				return 1;
		}
	}

	for (i = 0; i < NELEMS(files); i++) {
		if (!access(files[i], F_OK))
			return 1;
	}

	return 0;
}

static int addpeer(struct peer *pe0)
{
	struct peer *pe;

	pe = calloc(1, sizeof(*pe));
	if (pe == NULL)
		err(1, "malloc failed");
	*pe = *pe0;
	SIMPLEQ_INSERT_TAIL(&pqueue, pe, pe_link);

	return 0;
}

static void sys_seqno_load(void)
{
	char buf[32], *str;
	FILE *fp;

	fp = fopen(CacheFile, "r");
	if (!fp)
		return;

	while ((str = fgets(buf, sizeof(buf), fp))) {
		uint64_t val;
		char *end;

		if (str[strlen(str) - 1] == '\n')
			str[strlen(str) - 1] = 0;

		errno = 0;
		val = strtoull(str, &end, 10);
		if (val == 0 && end == str)
			break;	/* str was not a number */
		else if (val == ULLONG_MAX && errno)
			break; /* the value of str does not fit in unsigned long long */
		else if (*end)
			break; /* str began with a number but has junk left over at the end */

		sys_seqno = val;
		sys_seqno_init = 1; /* Ignore sys timestamp from now */
	}
	fclose(fp);
}

static void sys_seqno_save(void)
{
	static uint64_t prev = 0;
	FILE *fp;

	if (prev == sys_seqno)
		return;		/* no changes since last save */

	fp = fopen(CacheFile, "w");
	if (!fp)
		return;		/* best effort, ignore any errors */

	fprintf(fp, "%" PRIu64 "\n", sys_seqno);
	fclose(fp);

	prev = sys_seqno;

	sys_seqno_init = 1;	/* Ignore sys timestamp from now */
}

int usage(int code)
{
	printf("Usage:\n"
	       "  syslogd [-468AdFHKknsTtv?] [-a PEER] [-b NAME] [-f FILE] [-m INTERVAL]\n"
	       "                             [-P PID_FILE] [-p SOCK_PATH] [-r SIZE[:NUM]]\n"
	       "Options:\n"
	       "  -4        Force IPv4 only\n"
	       "  -6        Force IPv6 only\n"
	       "  -8        Allow all 8-bit data, e.g. unicode, does not affect control chars\n"
	       "  -A        Send to all addresses in DNS A, or AAAA record\n"
	       "  -a PEER   Allow PEER to use us as a remote syslog sink. Ignored when started\n"
	       "            with -s. Multiple -a options may be specified:\n"
	       "              ipaddr[/len][:port]   Accept messages from 'ipaddr', which may\n"
	       "                                    be IPv4 or IPv6 if enclosed with '[' and\n"
	       "                                    ']'.  The optional port may be a service\n"
	       "                                    name or a port number\n"
	       "              domainname[:port]     Accept messages where the reverse address\n"
	       "                                    lookup yields 'domainname' for the sender\n"
	       "                                    address.  'domainname' may contain special\n"
	       "                                    shell-style pattern characters like '*'\n"
	       "\n"
	       "  -b NAME   Bind to a specific address and/or port. Multiple -b options may be\n"
	       "            specified. Default is to listen on all interfaces on UDP port 514,\n"
	       "            unless also started with -s:\n"
	       "              address[:port]        Hostname or IP address, IPv6 addresses\n"
	       "                                    must be enclosed in '[' and ']'\n"
	       "              :port                 UDP port number, or service name\n"
	       "                                    default: 'syslog', port 514\n"
	       "\n"
	       "  -C FILE   File to cache last read kernel seqno, default: %s\n"
	       "            Note: syslogd relies on this file being removed at system reboot.\n"
	       "  -d        Enable debug mode, implicitly enables -F to prevent backgrounding\n"
	       "  -F        Run in foreground, required when monitored by init(1)\n"
	       "  -f FILE   Alternate .conf file, default: %s\n"
	       "  -H        Use hostname from message instead of address for remote messages\n"
	       "  -K        Disable kernel logging, useful in container use-cases\n"
	       "  -k        Allow logging with facility 'kernel', otherwise remapped to 'user'\n"
	       "  -m MINS   Interval between MARK messages, 0 to disable, default: 20 min\n"
	       "  -n        Disable DNS query for every request\n"
	       "  -P FILE   File to store the process ID, default: %s\n"
	       "  -p PATH   Path to UNIX domain socket, multiple -p create multiple sockets.\n"
	       "            Default, if no -p argument is given: %s\n"
	       "  -r S[:R]  Enable log rotation. The size argument (S) takes k/M/G qualifiers,\n"
	       "            e.g. 2M for 2 MiB.  The optional rotations argument default to 5.\n"
	       "            Rotation can also be defined per log file in %s\n"
	       "  -s        Operate in secure mode, do not log messages from remote machines.\n"
	       "            If specified twice, no socket at all will be opened, which also\n"
	       "            disables support for logging to remote machines.\n"
	       "  -t        Keep kernel timestamp, even after initial ring buffer emptying\n"
	       "  -T        Use local time and date for messages received from remote hosts\n"
	       "  -?        Show this help text\n"
	       "  -v        Show program version and exit\n"
	       "\n"
	       "Bug report address: %s\n",
	       _PATH_CACHE, _PATH_LOGCONF, _PATH_LOGPID, _PATH_LOG, _PATH_LOGCONF, PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
	printf("Project home page:  %s\n", PACKAGE_URL);
#endif

	return code;
}

int main(int argc, char *argv[])
{
	pid_t ppid = 1;
	int no_sys = 0;
	int pflag = 0;
	int bflag = 0;
	char *ptr;
	int ch;

	while ((ch = getopt(argc, argv, "468Aa:b:C:cdHFf:Kkm:nP:p:r:sTtv?")) != EOF) {
		switch ((char)ch) {
		case '4':
			family = PF_INET;
			break;

		case '6':
			family = PF_INET6;
			break;

		case '8':
			mask_C1 = 0;
			break;

		case 'A':
			send_to_all++;
			break;

		case 'a':		/* allow specific network addresses only */
			if (allowaddr(optarg) == -1)
				return usage(1);
			break;

		case 'b':
			bflag = 1;
			ptr = strchr(optarg, ':');
			if (ptr)
				*ptr++ = 0;
			addpeer(&(struct peer) {
				.pe_name = optarg,
				.pe_serv = ptr,
			});
			break;

		case 'C': /* kernel seqno cache file */
			CacheFile = optarg;
			break;

		case 'c':
			no_compress++;
			break;

		case 'd': /* debug */
			Debug = 1;
			Foreground = 1;
			break;

		case 'F': /* don't fork */
			Foreground = 1;
			break;

		case 'f': /* configuration file */
			ConfFile = optarg;
			break;

		case 'H':
			RemoteHostname = 1;
			break;

		case 'K':
			KernLog = 0;
			break;

		case 'k':		/* keep remote kern fac */
			KeepKernFac = 1;
			break;

		case 'm': /* mark interval */
			MarkInterval = atoi(optarg) * 60;
			break;

		case 'n':
			resolve = 0;
			break;

		case 'P':
			PidFile = optarg;
			break;

		case 'p': /* path to regular log socket */
			if (optarg[0] != '/') {
				warnx("Socket paths must be absolute (start with '/').");
				break;
			}

			pflag = 1;
			addpeer(&(struct peer) {
				.pe_name = optarg,
				.pe_mode = 0666,
			});
			break;

		case 'r':
			parse_rotation(optarg, &RotateSz, &RotateCnt);
			break;

		case 's':
			secure_opt++;
			break;

		case 'T':
			RemoteAddDate = 1;
			break;

		case 't':	/* keep/trust kernel timestamp always */
			KeepKernTime = 1;
			break;

		case 'v':
			printf("%s\n", version_info);
			return 0;

		case '?':
			return usage(0);

		default:
			return usage(1);
		}
	}

	if ((argc -= optind))
		return usage(1);

	/* Default to listen to :514 (syslog/udp) */
	if (!bflag)
		addpeer(&(struct peer) {
				.pe_name = NULL,
				.pe_serv = "syslog",
			});

	/* Figure out where to read system log messages from */
	if (!pflag) {
		/* Do we run under systemd-journald (Requires=syslog.socket)? */
		if (fcntl(3, F_GETFD) != -1) {
			if (socket_register(3, NULL, unix_cb, NULL) == -1)
				err(1, "failed registering syslog.socket (3)");
		} else {
			/* Default to _PATH_LOG for the UNIX domain socket */
			addpeer(&(struct peer) {
					.pe_name = _PATH_LOG,
					.pe_mode = 0666,
				});
		}
	}

	if (!Foreground && !Debug) {
		ppid = waitdaemon(30);
		if (ppid < 0)
			err(1, "Failed daemonizing");
	} else if (Debug) {
		debugging_on = 1;
		setlinebuf(stdout);
	}

	/*
	 * Attempt to open kernel log pipe.  On Linux we prefer
	 * /dev/kmsg and fall back to _PROC_KLOG, which on GLIBC
	 * systems is /proc/kmsg, and /dev/klog on *BSD.
	 */
	if (KernLog) {
		if (in_container()) {
			KernLog = 0;
			no_sys = 1;
			goto no_klogd;
		}

		sys_seqno_load();
		if (opensys("/dev/kmsg")) {
			if (opensys(_PATH_KLOG))
				warn("Kernel logging disabled, failed opening %s",
				     _PATH_KLOG);
			else
				kern_console_off();
		} else
			kern_console_off();
	}
no_klogd:
	consfile.f_type = F_CONSOLE;
	strlcpy(consfile.f_un.f_fname, ctty, sizeof(consfile.f_un.f_fname));

	logit("Starting.\n");
	boot_time_init();
	signal_init();
	init();

	/*
	 * Set up timer callbacks for -- MARK -- et al
	 */
	if (MarkInterval > 0) {
		int interval = MarkInterval / 2;

		if (interval < 30)
			interval = 30;
		timer_add(interval, domark, NULL);
	}
	timer_add(TIMERINTVL, doflush, NULL);

	/* Start 'em */
	timer_start();

	if (Debug) {
		logit("Debugging disabled, SIGUSR1 to turn on debugging.\n");
		debugging_on = 0;
	}

	/*
	 * Tell system we're up and running by creating /run/syslogd.pid
	 */
	if (pidfile(PidFile))
		logit("Failed creating %s: %s\n", PidFile, strerror(errno));

	/* Tell parent we're up and running */
	if (ppid != 1)
		kill(ppid, SIGALRM);

	/* Log if we disabled klogd */
	if (no_sys)
		NOTE("Running in a container, disabling klogd.");

	/* Main loop begins here. */
	for (;;) {
		int rc;

		rc = socket_poll(NULL);
		if (restart > 0) {
			restart--;
			logit("\nReceived SIGHUP, reloading syslogd.\n");
			init();

			/* Acknowledge SIGHUP by touching our PID file */
			if (pidfile(PidFile))
				ERR("Failed touching %s", PidFile);
			continue;
		}

		if (rotate_signal > 0) {
			rotate_signal = 0;
			logit("\nReceived SIGUSR2, forcing log rotation.\n");
			rotate_all_files();
		}

		if (rc < 0 && errno != EINTR)
			ERR("select()");

		if (KernLog)
			sys_seqno_save();
	}
}

/*
 * Read /dev/klog while data are available, split into lines.
 */
static void kernel_cb(int fd, void *arg)
{
	char *p, *q, line[MAXLINE + 1];
	int len, i;

	len = 0;
	for (;;) {
		i = read(fd, line + len, MAXLINE - 1 - len);
		if (i > 0) {
			line[i + len] = 0;
		} else {
			if (i < 0) {
				switch (errno) {
				case EPIPE: /* linux, log buffer overrun */
					ERRX("Kernel log buffer filling up too quick, "
					     "or too small log buffer, "
					     "adjust kernel CONFIG_LOG_BUF_SHIFT");
				case EINTR:
				case EAGAIN:
					break;

				case EINVAL:
					break;

				default:
					ERR("klog read()");
					socket_close(fd);
					break;
				}
			}
			break;
		}

		for (p = line; (q = strchr(p, '\n')) != NULL; p = q + 1) {
			*q = 0;
			printsys(p);
		}
		len = strlen(p);
		if (len >= MAXLINE - 1) {
			printsys(p);
			len = 0;
		}
		if (len > 0)
			memmove(line, p, len + 1);
	}

	if (len > 0) {
		line[len] = 0;
		printsys(line);
	}
}

static int opensys(const char *file)
{
	struct stat st;
	int fd;

	/*
	 * In some (container) use-cases /dev/kmsg might not be a proper
	 * FIFO, which may lead to CPU overload and possible loss of
	 * function.  This check, along with the in_container() function
	 * is an attempt to remedy such scenarios.  It's merely a sanity
	 * check, so ignore any TOCTOU warnings this might cause.
	 */
	if (stat(file, &st) || !S_ISCHR(st.st_mode))
		return 1;

	fd = open(file, O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
	if (fd < 0)
		return 1;

	if (socket_register(fd, NULL, kernel_cb, NULL) < 0) {
		close(fd);
		return 1;
	}

	return 0;
}

static void unix_cb(int sd, void *arg)
{
	ssize_t msglen;
	char msg[MAXLINE + 1] = { 0 };

	msglen = recv(sd, msg, sizeof(msg) - 1, 0);
	logit("Message from UNIX socket #%d: %s\n", sd, msg);
	if (msglen <= 0) {
		if (msglen < 0 && errno != EINTR)
			ERR("UNIX recv()");
		return;
	}
	msg[msglen] = 0;

	parsemsg(LocalHostName, msg);
}

static void create_unix_socket(struct peer *pe)
{
	struct sockaddr_un sun;
	struct addrinfo ai;
	int sd = -1;

	if (pe->pe_socknum)
		return;		/* Already set up */

	memset(&ai, 0, sizeof(ai));
	ai.ai_addr = (struct sockaddr *)&sun;
	ai.ai_addrlen = sizeof(sun);
	ai.ai_family = sun.sun_family = AF_UNIX;
	ai.ai_socktype = SOCK_DGRAM;
	ai.ai_protocol = pe->pe_mode;
	strlcpy(sun.sun_path, pe->pe_name, sizeof(sun.sun_path));

	sd = socket_create(&ai, unix_cb, NULL);
	if (sd < 0)
		goto err;

	logit("Created UNIX socket %d ...\n", sd);
	pe->pe_sock[pe->pe_socknum++] = sd;
	return;
err:
	ERR("cannot create %s", pe->pe_name);
}

static void unmapped(struct sockaddr *sa)
{
	struct sockaddr_in6 *sin6;
	struct sockaddr_in sin;

	if (sa == NULL ||
#ifdef HAVE_SA_LEN
	    sa->sa_len != sizeof(*sin6) ||
#endif
	    sa->sa_family != AF_INET6)
		return;
	sin6 = satosin6(sa);
	if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
		return;
	sin = (struct sockaddr_in){
		.sin_family = AF_INET,
#ifdef HAVE_SA_LEN
		.sin_len = sizeof(sin),
#endif
		.sin_port = sin6->sin6_port
	};
	memcpy(&sin.sin_addr, &sin6->sin6_addr.s6_addr[12], sizeof(sin.sin_addr));
	memcpy(sa, &sin, sizeof(sin));
}

static void inet_cb(int sd, void *arg)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	const char *hname;
	socklen_t sslen;
	ssize_t len;
	char msg[MAXLINE + 1] = { 0 };

	sslen = sizeof(ss);
	len = recvfrom(sd, msg, sizeof(msg) - 1, 0, sa, &sslen);
	if (len <= 0) {
		if (len < 0 && errno != EINTR && errno != EAGAIN)
			ERR("INET recvfrom()");
		return;
	}
	msg[len] = 0;

	hname = cvthname((struct sockaddr *)&ss, sslen);
	unmapped(sa);
	if (!validate(sa, hname)) {
		logit("Message from %s was ignored.\n", hname);
		return;
	}

	parsemsg(hname, msg);
}

static int nslookup(const char *host, const char *service, struct addrinfo **ai)
{
	struct addrinfo hints;
	const char *node = host;

	if (!node || !node[0])
		node = NULL;

	/* Reset resolver cache and retry name lookup */
	res_init();

	logit("nslookup '%s:%s'\n", node ?: "none", service);
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags    = !node ? AI_PASSIVE : 0;
	hints.ai_family   = family;
	hints.ai_socktype = SOCK_DGRAM;

	return getaddrinfo(node, service, &hints, ai);
}

static void create_inet_socket(struct peer *pe)
{
	struct addrinfo *ai, *res;
	int sd, err;

	err = nslookup(pe->pe_name, pe->pe_serv, &res);
	if (err) {
		ERRX("%s/udp service unknown: %s", pe->pe_serv,
		     gai_strerror(err));
		return;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (pe->pe_socknum + 1 >= NELEMS(pe->pe_sock)) {
			WARN("Only %zd IP addresses per socket supported.",
			     NELEMS(pe->pe_sock));
			break;
		}

		if (SecureMode)
			ai->ai_flags |= AI_SECURE;
		else
			ai->ai_flags &= ~AI_SECURE;

		sd = socket_create(ai, inet_cb, NULL);
		if (sd < 0)
			continue;

		logit("Created inet socket %d for %s:%s ...\n", sd,
		      pe->pe_name, pe->pe_serv);
		pe->pe_sock[pe->pe_socknum++] = sd;
	}

	freeaddrinfo(res);
}

void untty(void)
{
#ifdef HAVE_SETSID
	if (!Debug)
		setsid();
#endif
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
	while (*msg && *msg >= '!' && *msg <= '~' && *msg != '=' &&	\
	    *msg != ']' && *msg != '"')					\
		++msg;							\
	FAIL_IF("STRUCTURED-NAME", start == msg);			\
} while (0)
	IF_NOT_NILVALUE(buffer.sd) {
		buffer.sd = msg;
		/* SD-ELEMENT. */
		while (*msg && *msg == '[') {
			++msg;
			/* SD-ID. */
			PARSE_SD_NAME();
			/* SD-PARAM. */
			while (*msg && *msg == ' ') {
				++msg;
				/* PARAM-NAME. */
				PARSE_SD_NAME();
				PARSE_CHAR("STRUCTURED-NAME", '=');
				PARSE_CHAR("STRUCTURED-NAME", '"');
				while (*msg && *msg != '"') {
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
	struct logtime timestamp_remote = { 0 };
	struct buf_msg buffer;
	struct tm tm_parsed;
	size_t i, msglen;
	char line[MAXLINE + 1];

	memset(&buffer, 0, sizeof(buffer));
	buffer.recvhost = (char *)from;
	buffer.pri = pri;
	buffer.msg = line;

	/*
	 * Parse the TIMESTAMP provided by the remote side. If none is
	 * found, assume this is not an RFC 3164 formatted message,
	 * only containing a TAG and a MSG.
	 */
	if (strptime(msg, RFC3164_DATEFMT, &tm_parsed) ==
	    msg + RFC3164_DATELEN && msg[RFC3164_DATELEN] == ' ') {

		msg += RFC3164_DATELEN + 1;

		if (!RemoteAddDate) {
			struct timeval tv;
			time_t t_remote;
			struct tm tm_now;
			int year;

			if (gettimeofday(&tv, NULL) == -1) {
				tv.tv_sec  = time(NULL);
				tv.tv_usec = 0;
			}

			/*
			 * As the timestamp does not contain the year
			 * number, daylight saving time information, nor
			 * a time zone, attempt to infer it. Due to
			 * clock skews, the timestamp may even be part
			 * of the next year. Use the last year for which
			 * the timestamp is at most one week in the
			 * future.
			 *
			 * This loop can only run for at most three
			 * iterations before terminating.
			 */
			localtime_r(&tv.tv_sec, &tm_now);
			for (year = tm_now.tm_year + 1;; --year) {
				if (year < tm_now.tm_year - 1)
					break;
				timestamp_remote.tm = tm_parsed;
				timestamp_remote.tm.tm_year = year;
				timestamp_remote.tm.tm_isdst = -1;
				t_remote = mktime(&timestamp_remote.tm);
				if ((t_remote != (time_t)-1) &&
				    (t_remote - tv.tv_sec) < 7 * 24 * 60 * 60)
					break;
			}
			buffer.timestamp = timestamp_remote;
			buffer.timestamp.usec = tv.tv_usec;
		}
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

	if (buffer.hostname == NULL || !RemoteHostname)
		buffer.hostname = (char *)from;

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

	/*
	 * Message looks OK, update current time and log it
	 */
	timer_update();

	/* Parse VERSION. */
	msg += i + 1;
	if (msg[0] == '1' && msg[1] == ' ')
		parsemsg_rfc5424(from, pri, msg + 2);
	else
		parsemsg_rfc3164(from, pri, msg);
}

/*
 * Take a raw input line from /dev/klog, Linux /proc/klog, or Linux
 * /dev/kmsg, split and format similar to syslog().
 */
void printsys(char *msg)
{
	struct buf_msg buffer;
	char line[MAXLINE + 1];
	uint64_t ustime = 0;
	uint64_t seqno = 0;
	char *lp, *p, *q;
	int c;

	lp = line;
	for (p = msg; *p != '\0';) {
		memset(&buffer, 0, sizeof(buffer));
		buffer.app_name = "kernel";
		buffer.hostname = LocalHostName;
		buffer.pri = DEFSPRI;
		buffer.msg = line;

		if (*p == '<') {
			/* /proc/klog or *BSD /dev/klog */
			p++;
			buffer.pri = 0;
			while (isdigit(*p))
				buffer.pri = 10 * buffer.pri + (*p++ - '0');
			if (*p == '>')
				p++;
		} else if (isdigit(*p)) {
			/* Linux /dev/kmsg: "pri,seq#,msec,flag[,..];msg" */
			time_t now;

			/* pri */
			buffer.pri = 0;
			while (isdigit(*p))
				buffer.pri = 10 * buffer.pri + (*p++ - '0');
			if (*p == ',')
				p++;

			/* seq# */
			while (isdigit(*p))
				seqno = 10 * seqno + (*p++ - '0');

			/*
			 * Check if logged already (we've been restarted)
			 * Account for wrap-around at 18446744073709551615
			 */
			if (sys_seqno > 0 && seqno <= sys_seqno) {
				/* allow dupes around the edge */
				if (sys_seqno < 18446744073709551000ULL)
					return;
			}
			sys_seqno = seqno;
			if (*p == ',')
				p++;

			/* timestamp */
			while (isdigit(*p))
				ustime = 10 * ustime + (*p++ - '0');

			/*
			 * When syslogd starts up, we assume this happens at
			 * close to system boot, we read all kernel logs from
			 * /dev/kmsg (Linux) and calculate the precise time
			 * stamp using boot_time + usec to get the time of a
			 * log entry.  However, since the kernel time stamp
			 * is not adjusted for suspend/resume it can be many
			 * days (!) off after a few weeks of uptime.  It has
			 * turned out to be quite an interesting problem to
			 * compensate for, so at runtime we instead use the
			 * current time of any new kernel messages.
			 *     -- Joachim Wiberg Nov 23, 2021
			 */
			if (KeepKernTime || !sys_seqno_init) {
				now = boot_time + ustime / 1000000;
				localtime_r(&now, &buffer.timestamp.tm);
			} else {
				struct timeval tv;

				now = time(NULL);
				if (gettimeofday(&tv, NULL) == -1) {
					tv.tv_sec  = time(NULL);
					tv.tv_usec = 0;
				}
				ustime = tv.tv_usec * 1000000;
			}

			localtime_r(&now, &buffer.timestamp.tm);
			buffer.timestamp.usec = ustime % 1000000;

			/* skip flags for now */
			q = strchr(p, ';');
			if (q)
				p = ++q;
		} else if (*p == ' ') {
			/* Linux /dev/kmsg continuation line w/ SUBSYSTEM= DEVICE=, skip */
			return;
		}
#ifdef __NuttX__
		else if (*p == '[') {
				p++;
#ifdef CONFIG_SYSLOG_TIMESTAMP_FORMATTED
				if (strptime(p, CONFIG_SYSLOG_TIMESTAMP_FORMAT, &buffer.timestamp.tm) == NULL)
					return;
				p = strchr(p, ']');
				if (p == NULL)
					return;
#else
				time_t sec = boot_time + strtoul(p ,&p, 0);
				if (*p++ != '.') {
					return;
				}
				localtime_r(&sec, &buffer.timestamp.tm);
				buffer.timestamp.usec = atoi(p) * 1000;
				p = strchr(p, ']');
				if (p == NULL)
					return;
#endif

#ifdef CONFIG_SMP
				p = strchr(p, '[');
				if (p == NULL)
					return;
				buffer.sd = ++p;
				p = strchr(p, ']');
				if (p == NULL)
					return;
				*p++ = '\0';
#endif

#ifdef CONFIG_SYSLOG_PROCESSID
				p = strchr(p, '[');
				if (p == NULL)
					return;
				buffer.proc_id = ++p;
				p = strchr(p, ']');
				if (p == NULL)
					return;

				*p++ = '\0';
#endif

#ifdef CONFIG_SYSLOG_PRIORITY
				static const char * PriorityNames[] = {
					" EMERG", " ALERT", "  CRIT", " ERROR",
					"  WARN", "NOTICE", "  INFO", " DEBUG"
				};
				p = strchr(p, '[');
				if (p == NULL)
					return;
				p = p + 1;

				for (uint8_t i = 0; i <= LOG_DEBUG; i++) {
					if (strncmp(p, PriorityNames[i],
						    strlen(PriorityNames[i])) == 0) {
						buffer.pri = i;
						p += strlen(PriorityNames[i]);
						break;
					}
				}
				p = strchr(p, ']');
				if (p == NULL)
					return;
				p += 2;
#endif

#ifdef CONFIG_SYSLOG_PREFIX
				p = strchr(p, '[');
				if (p == NULL)
					return;
				buffer.hostname = p + 1;
				p = strchr(p, ']');
				if (p == NULL)
					return;
				*p++ = '\0';
#endif

#if CONFIG_TASK_NAME_SIZE > 0 && defined(CONFIG_SYSLOG_PROCESS_NAME)
				buffer.app_name = p;
				p = strchr(p, ':');
				if (p == NULL)
					return;
				*(p + 1) = '\0';
				p += 2;
#endif
		}
#endif
		else {
			/* kernel printf's come out on console */
			buffer.flags |= IGN_CONS;
		}

		if (buffer.pri & ~(LOG_FACMASK | LOG_PRIMASK))
			buffer.pri = DEFSPRI;

		/*
		 * Check for user writing to /dev/kmsg before /dev/log
		 * is up.  Syntax to write: <PRI>APP_NAME[PROC_ID]:msg
		 */
		if (buffer.pri & LOG_FACMASK) {
			for (q = p; *q && !isspace(*q) && *q != '['; q++)
				;

			if (*q == '[') {
				char *ptr = &q[1];

				while (*ptr && isdigit(*ptr))
					ptr++;

				if (ptr[0] == ']' && ptr[1] == ':') {
					*ptr++ = 0;
					*q++   = 0;

					buffer.app_name = p;
					buffer.proc_id  = q;

					/* user log message cont. here */
					p = &ptr[1];
				}
			}
		}

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

static void check_timestamp(struct buf_msg *buffer)
{
	struct logtime zero;
	struct logtime now;
	struct timeval tv;

	memset(&zero, 0, sizeof(zero));
	if (memcmp(&buffer->timestamp, &zero, sizeof(zero)))
		return;

	if (gettimeofday(&tv, NULL) == -1) {
		tv.tv_sec  = time(NULL);
		tv.tv_usec = 0;
	}

	localtime_r(&tv.tv_sec, &now.tm);
	now.usec = tv.tv_usec;
	buffer->timestamp = now;
}

/*
 * Logs a message to the appropriate log files, users, etc. based on the
 * priority. Log messages are always formatted according to RFC 3164,
 * even if they were in RFC 5424 format originally, The MSGID and
 * STRUCTURED-DATA fields are thus discarded for the time being.
 */
static void logmsg(struct buf_msg *buffer)
{
	struct filed *f;
	sigset_t mask;
	size_t savedlen;
	char saved[MAXSVLINE];
	int fac, prilev;

	logit("logmsg: %s, flags %x, from %s, app-name %s procid %s msgid %s sd %s msg %s\n",
	      textpri(buffer->pri), buffer->flags,
	      buffer->hostname ? buffer->hostname : "nil",
	      buffer->app_name ? buffer->app_name : "nil",
	      buffer->proc_id  ? buffer->proc_id  : "nil",
	      buffer->msgid    ? buffer->msgid    : "nil",
	      buffer->sd       ? buffer->sd       : "nil",
	      buffer->msg);

	/* Messages generated by syslogd itself may not have a timestamp */
	check_timestamp(buffer);

	/* extract facility and priority level */
	if (buffer->flags & MARK)
		fac = LOG_NFACILITIES;
	else
		fac = LOG_FAC(buffer->pri);

	/* Check maximum facility number. */
	if (fac > LOG_NFACILITIES)
		return;

	prilev = LOG_PRI(buffer->pri);

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGALRM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	/* log the message to the particular outputs */
	if (!Initialized) {
		f = &consfile;

		f->f_file = open(ctty, O_WRONLY | O_NOCTTY);
		if (f->f_file >= 0) {
			untty();
			fprintlog_first(f, buffer);
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

	SIMPLEQ_FOREACH(f, &fhead, f_link) {
		/* skip messages that are incorrect priority */
		if ((f->f_pmask[fac] == INTERNAL_INVPRI) ||
		    ((f->f_pmask[fac] & (1 << prilev)) == 0))
			continue;

		/* skip message to console if it has already been printed */
		if (f->f_type == F_CONSOLE && (buffer->flags & IGN_CONS))
			continue;

		/* don't output marks to recently written files */
		if (buffer->flags & MARK) {
			time_t t_now = timer_now();

			if (f->f_time + MarkInterval > t_now)
				continue;
			if (t_now - f->f_time < MarkInterval / 2)
				continue;
		}

		/*
		 * suppress duplicate lines to this file
		 */
		if (no_compress - (f->f_type != F_PIPE) < 1 &&
		    (buffer->flags & MARK) == 0 && savedlen == f->f_prevlen &&
		    !strcmp(saved, f->f_prevline)) {
			f->f_lasttime = buffer->timestamp;
			f->f_prevcount++;
			logit("msg repeated %lu times, %ld sec of %d.\n",
			      f->f_prevcount, timer_now() - f->f_time,
			      repeatinterval[f->f_repeatcount]);

			/*
			 * If domark would have logged this by now,
			 * flush it now (so we don't hold isolated messages),
			 * but back off so we'll flush less often
			 * in the future.
			 */
			if (timer_now() > REPEATTIME(f)) {
				fprintlog_successive(f, buffer->flags);
				BACKOFF(f);
			}
		} else {
			/* new line, save it */
			if (f->f_prevcount)
				fprintlog_successive(f, 0);

			f->f_prevpri = buffer->pri;
			f->f_repeatcount = 0;
			f->f_lasttime = buffer->timestamp;
			strlcpy(f->f_prevhost, buffer->hostname, sizeof(f->f_prevhost));
			strlcpy(f->f_prevline, saved, sizeof(f->f_prevline));
			f->f_prevlen = savedlen;
			fprintlog_first(f, buffer);
		}
	}

	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

static void logrotate(struct filed *f)
{
	struct stat statf;

	if (!f->f_rotatesz)
		return;

	if (fstat(f->f_file, &statf))
		return;

	/* bug (mostly harmless): can wrap around if file > 4gb */
	if (S_ISREG(statf.st_mode) && statf.st_size > f->f_rotatesz)
		rotate_file(f, &statf);
}

static void rotate_file(struct filed *f, struct stat *stp_or_null)
{
	if (f->f_rotatecount > 0) { /* always 0..999 */
		struct stat st_stack;
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
			snprintf(oldFile, len, "%s.%d", f->f_un.f_fname, i - 1);
			snprintf(newFile, len, "%s.%d", f->f_un.f_fname, i);

			if (!rename(oldFile, newFile) && i > 0) {
				size_t clen = 18 + strlen(newFile) + 1;
				char cmd[clen];

				snprintf(cmd, sizeof(cmd), "gzip -f %s", newFile);
				system(cmd);
			}
		}

		/* newFile == "f.0" now */
		snprintf(newFile, len, "%s.0", f->f_un.f_fname);
		(void)rename(f->f_un.f_fname, newFile);

		/* Get mode of open descriptor if not yet */
		if (stp_or_null == NULL) {
			stp_or_null = &st_stack;
			if (fstat(f->f_file, stp_or_null))
				stp_or_null = NULL;
		}

		close(f->f_file);

		f->f_file = open(f->f_un.f_fname, O_CREATE | O_NONBLOCK | O_NOCTTY,
				 (stp_or_null ? stp_or_null->st_mode : 0644));
		if (f->f_file < 0) {
			f->f_type = F_UNUSED;
			ERR("Failed re-opening log file %s after rotation", f->f_un.f_fname);
			return;
		}

		if (!SIMPLEQ_EMPTY(&nothead))
			notifier_invoke(f->f_un.f_fname);
	}
	ftruncate(f->f_file, 0);
}

static void rotate_all_files(void)
{
	struct filed *f;

	SIMPLEQ_FOREACH(f, &fhead, f_link) {
		if (f->f_type == F_FILE && f->f_rotatesz)
			rotate_file(f, NULL);
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

void fprintlog_write(struct filed *f, struct iovec *iov, int iovcnt, int flags)
{
	struct addrinfo *ai;
	struct msghdr msg;
	ssize_t len = 0;
	ssize_t lsent;
	time_t fwd_suspend;

	switch (f->f_type) {
	case F_UNUSED:
		f->f_time = timer_now();
		logit("\n");
		break;

	case F_FORW_SUSP:
		fwd_suspend = timer_now() - f->f_time;
		if (fwd_suspend >= INET_SUSPEND_TIME) {
			logit("\nForwarding suspension over, retrying FORW ");
			f->f_type = F_FORW_UNKN;
			goto f_forw_unkn;
		} else {
			logit(" %s:%s\n", f->f_un.f_forw.f_hname, f->f_un.f_forw.f_serv);
			logit("Forwarding suspension not over, time left: %d.\n",
			      (int)(INET_SUSPEND_TIME - fwd_suspend));
		}
		break;

	case F_FORW_UNKN:
		logit("\n");
	f_forw_unkn:
		forw_lookup(f);
		if (f->f_type == F_FORW)
			goto f_forw;
		break;

	case F_FORW:
	f_forw:
		logit(" %s:%s\n", f->f_un.f_forw.f_hname, f->f_un.f_forw.f_serv);
		f->f_time = timer_now();

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = iov;
		msg.msg_iovlen = iovcnt;

		for (int i = 0; i < iovcnt; i++) {
//			logit("iov[%d] => %s\n", i, (char *)iov[i].iov_base);
			len += iov[i].iov_len;
		}

		lsent = 0;
		for (ai = f->f_un.f_forw.f_addr; ai; ai = ai->ai_next) {
			int sd;

			sd = socket_ffs(ai->ai_family);
			if (sd != -1) {
				char buf[64] = { 0 };

				msg.msg_name = ai->ai_addr;
				msg.msg_namelen = ai->ai_addrlen;
				lsent = sendmsg(sd, &msg, 0);

				if (AF_INET == ai->ai_family) {
					struct sockaddr_in *sin;

					sin = (struct sockaddr_in *)ai->ai_addr;
					inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
				} else {
					struct sockaddr_in6 *sin6;

					sin6 = (struct sockaddr_in6 *)ai->ai_addr;
					inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
				}

				logit("Sent %zd bytes to %s on socket %d ...\n", lsent, buf, sd);
				if (lsent == len)
					break;
			}
			if (lsent == len && !send_to_all)
				break;
		}
		if (lsent != len) {
			switch (errno) {
			case ENOBUFS:
			case ENETDOWN:
			case ENETUNREACH:
			case EHOSTUNREACH:
			case EHOSTDOWN:
			case EADDRNOTAVAIL:
				/* Ignore and try again later, with the next message */
				break;
			/* case EBADF: */
			/* case EACCES: */
			/* case ENOTSOCK: */
			/* case EFAULT: */
			/* case EMSGSIZE: */
			/* case EAGAIN: */
			/* case ENOBUFS: */
			/* case ECONNREFUSED: */
			default:
				f->f_type = F_FORW_SUSP;
				ERR("INET sendto(%s:%s)", f->f_un.f_forw.f_hname, f->f_un.f_forw.f_serv);
				if (f->f_un.f_forw.f_addr) {
					freeaddrinfo(f->f_un.f_forw.f_addr);
					f->f_un.f_forw.f_addr = NULL;
				}
			}
		}
		break;

	case F_CONSOLE:
		f->f_time = timer_now();
		if (flags & IGN_CONS) {
			logit(" (ignored).\n");
			break;
		}
		/* FALLTHROUGH */

	case F_TTY:
	case F_FILE:
	case F_PIPE:
		f->f_time = timer_now();
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

		if (writev(f->f_file, &iov[1], iovcnt - 1) < 0) {
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
					ERR("Failed writing and re-opening %s", f->f_un.f_fname);
				} else {
					untty();
					goto again;
				}
			} else {
				f->f_type = F_UNUSED;
				errno = e;
				ERR("Failed writing to %s", f->f_un.f_fname);
			}
		} else if (f->f_type == F_FILE && (f->f_flags & SYNC_FILE))
			(void)fsync(f->f_file);
		break;

	case F_USERS:
	case F_WALL:
		f->f_time = timer_now();
		logit("\n");
		pushiov(iov, iovcnt, "\r\n");
		wallmsg(f, &iov[0], iovcnt);
		break;
	} /* switch */

	if (f->f_type != F_FORW_UNKN)
		f->f_prevcount = 0;
}

#define fmtlogit(bm) logit("%s(%d, 0x%02x, %s, %s, %s, %s, %s, %s)", __func__,		\
			   bm->pri, bm->flags, bm->hostname ? bm->hostname : "-",	\
			   bm->app_name ? bm->app_name : "-",				\
			   bm->proc_id ? bm->proc_id : "-",				\
			   bm->msgid ? bm->msgid : "-",					\
			   bm->sd ? bm->sd : "-", bm->msg ? bm->msg : "-")

static int fmt3164(struct buf_msg *buffer, char *fmt, struct iovec *iov, size_t iovmax)
{
	int i = 0;

	fmtlogit(buffer);

	/* Notice difference to RFC5424, in RFC3164 there is *no* space! */
	snprintf(buffer->pribuf, sizeof(buffer->pribuf), "<%d>", buffer->pri);
	pushiov(iov, i, buffer->pribuf);

	/*
	 * sysklogd < 2.0 had the traditional BSD format for remote syslog
	 * which did not include the timestamp or the hostname.
	 */
	if (fmt) {
		strftime(buffer->timebuf, sizeof(buffer->timebuf), fmt, &buffer->timestamp.tm);
		pushiov(iov, i, buffer->timebuf);
		pushsp(iov, i);

		pushiov(iov, i, buffer->hostname ? buffer->hostname : buffer->recvhost);
		pushsp(iov, i);
	}

	if (buffer->app_name) {
		/*
		 * RFC3164, sec 4.1.3: "The TAG is a string of ABNF
		 * alphanumeric characters that MUST NOT exceed 32
		 * characters."
		 */
		iov[i].iov_base = buffer->app_name;
		iov[i].iov_len  = MIN(strlen(buffer->app_name), 32);
		i++;

		if (buffer->proc_id) {
			pushiov(iov, i, "[");
			pushiov(iov, i, buffer->proc_id);
			pushiov(iov, i, "]");
		}
		pushiov(iov, i, ":");
		pushsp(iov, i);
	}

	pushiov(iov, i, buffer->msg);

	return i;
}

/* <PRI>1 2003-08-24T05:14:15.000003-07:00 hostname app-name procid msgid sd msg */
static int fmt5424(struct buf_msg *buffer, char *fmt, struct iovec *iov, size_t iovmax)
{
	suseconds_t usec;
	int i = 0;

	fmtlogit(buffer);
	strftime(buffer->timebuf, sizeof(buffer->timebuf), fmt, &buffer->timestamp.tm);

	/* Add colon to the time zone offset, which %z doesn't do */
	buffer->timebuf[32] = '\0';
	buffer->timebuf[31] = buffer->timebuf[30];
	buffer->timebuf[30] = buffer->timebuf[29];
	buffer->timebuf[29] = ':';

	/* Overwrite space for microseconds with actual value */
	usec = buffer->timestamp.usec;
	for (int j = 25; j >= 20; --j) {
		buffer->timebuf[j] = usec % 10 + '0';
		usec /= 10;
	}

	/* RFC 5424 defines itself as v1, notice space before time, c.f. RFC3164 */
	snprintf(buffer->pribuf, sizeof(buffer->pribuf), "<%d>1 ", buffer->pri);
	pushiov(iov, i, buffer->pribuf);

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

static void fprintlog_first(struct filed *f, struct buf_msg *buffer)
{
	struct iovec iov[20];
	int iovcnt;

	logit("Called fprintlog_first(), ");

	/* Messages generated by syslogd itself may not have a timestamp */
	check_timestamp(buffer);

	if (f->f_type != F_FORW_SUSP && f->f_type != F_FORW_UNKN) {
		f->f_time = timer_now();
		f->f_prevcount = 0;
	}

	if (f->f_flags & RFC5424)
		iovcnt = fmt5424(buffer, RFC5424_DATEFMT, iov, NELEMS(iov));
	else if (f->f_flags & RFC3164)
		iovcnt = fmt3164(buffer, RFC3164_DATEFMT, iov, NELEMS(iov));
	else
		iovcnt = fmt3164(buffer, BSDFMT_DATEFMT, iov, NELEMS(iov));

	logit(" logging to %s", TypeNames[f->f_type]);
	fprintlog_write(f, iov, iovcnt, buffer->flags);
}

static void fprintlog_successive(struct filed *f, int flags)
{
	struct buf_msg buffer;
	char msg[80];

	assert(f->f_prevcount > 0);

	memset(&buffer, 0, sizeof(buffer));
	buffer.hostname = f->f_prevhost;
	buffer.pri = f->f_prevpri;
	buffer.timestamp = f->f_lasttime;
	buffer.flags = flags;

	snprintf(msg, sizeof(msg), "last message buffered %zu times",
		 f->f_prevcount);
	buffer.msg = msg;

	fprintlog_first(f, &buffer);
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
#ifdef HAVE_UTMP_H
	static int reenter = 0;
	struct utmp *uptr;
	struct utmp  ut;
	char p[sizeof(_PATH_DEV) + UNAMESZ + 1];
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
		time_t t_now = time(NULL);

		(void)signal(SIGTERM, SIG_DFL);
		(void)alarm(0);

		(void)snprintf(greetings, sizeof(greetings),
		               "\r\n\7Message from syslogd@%s at %.24s ...\r\n",
		               (char *)iov[3].iov_base, ctime(&t_now));
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
			snprintf(p, sizeof(p), "%s%s", _PATH_DEV, ut.ut_line);

			if (f->f_type == F_WALL) {
				/* Overwrite time, skip space */
				iov[1].iov_base = greetings;
				iov[1].iov_len = len;
				iov[2].iov_len = 0;
				/* Skip hostname and space, we know where we're at */
				iov[3].iov_len = 0;
				iov[4].iov_len = 0;
			}
			if (setjmp(ttybuf) == 0) {
				(void)signal(SIGALRM, endtty);
				(void)alarm(15);

				/* open terminal, skip <PRI> field for all cases */
				ttyf = open(p, O_WRONLY | O_NOCTTY);
				if (ttyf >= 0) {
					struct stat st;
					int rc;

					rc = fstat(ttyf, &st);
					if (rc == 0 && (st.st_mode & S_IWRITE))
						(void)writev(ttyf, &iov[1], iovcnt - 1);
					close(ttyf);
				}
			}
			(void)alarm(0);
		}
		exit(0);
	}
	/* close the user login file */
	endutent();
	reenter = 0;
#endif
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
const char *cvthname(struct sockaddr *f, socklen_t len)
{
	static char hname[NI_MAXHOST], ip[NI_MAXHOST];
	char *p;
	int err;

	err = getnameinfo(f, len, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
	if (err) {
		logit("Malformed from address: %s\n", gai_strerror(err));
		return "???";
	}

	if (!resolve)
		return ip;

	err = getnameinfo(f, len, hname, sizeof(hname), NULL, 0, NI_NAMEREQD);
	if (err) {
		logit("Host name for your address (%s) unknown: %s\n",
		      ip, gai_strerror(err));
		return ip;
	}

	/*
	 * Convert to lower case, just like LocalDomain in init()
	 */
	for (p = hname; *p; p++) {
		if (isupper(*p))
			*p = tolower(*p);
	}

	/*
	 * BSD has trimdomain(h1, ...), we implement our own here.
	 * Notice that the string still contains the fqdn, but your
	 * hostname and domain are separated by a '\0'.
	 */
	if ((p = strchr(hname, '.'))) {
		if (strcmp(p + 1, LocalDomain) == 0) {
			*p = '\0';
			return hname;
		}
	}

	return hname;
}

/*
 * Base function for domark(), ERR(), etc.
 */
void flog(int pri, char *fmt, ...)
{
	struct buf_msg buffer;
	va_list ap;
	char proc_id[10];
	char buf[BUFSIZ];

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	logit("flog<%d>: %s\n", pri, buf);

	(void)snprintf(proc_id, sizeof(proc_id), "%d", getpid());
	memset(&buffer, 0, sizeof(buffer));
	buffer.hostname = LocalHostName;
	buffer.app_name = "syslogd";
	buffer.proc_id  = proc_id;
	buffer.pri = pri;
	buffer.msg = buf;
	if (pri & INTERNAL_MARK)
		buffer.flags = MARK;

	logmsg(&buffer);
}

static void forw_lookup(struct filed *f)
{
	char *host = f->f_un.f_forw.f_hname;
	char *serv = f->f_un.f_forw.f_serv;
	struct addrinfo *ai;
	int err, first;
	time_t diff;

	if (SecureMode > 1) {
		if (f->f_un.f_forw.f_addr)
			freeaddrinfo(f->f_un.f_forw.f_addr);
		f->f_un.f_forw.f_addr = NULL;
		f->f_type = F_FORW_UNKN;
		return;
	}

	/* Called from cfline() for initial lookup? */
	first = f->f_type == F_UNUSED ? 1 : 0;

	/*
	 * Not INET_SUSPEND_TIME, but back off a few seconds at least
	 * to prevent syslogd from hammering the resolver for every
	 * little message that is logged.  E.g., at boot when we read
	 * the kernel ring buffer.
	 */
	diff = timer_now() - f->f_time;
	if (!first && diff < 5)
		return;

	err = nslookup(host, serv, &ai);
	if (err) {
		f->f_type = F_FORW_UNKN;
		f->f_time = timer_now();
		if (!first && !(f->f_flags & SUSP_RETR))
			WARN("Failed resolving '%s:%s': %s", host, serv, gai_strerror(err));
		f->f_flags |= SUSP_RETR; /* Retry silently */
		return;
	}

	f->f_flags &= ~SUSP_RETR;
	f->f_type = F_FORW;
	f->f_un.f_forw.f_addr = ai;
	f->f_prevcount = 0;

	if (!first)
		NOTE("Successfully resolved '%s:%s', initiating forwarding.", host, serv);
}

void domark(void *arg)
{
	static time_t t_last = 0;
	time_t t_now;

	t_now = timer_now();
	if (t_now >= t_last + MarkInterval) {
		flog(INTERNAL_MARK | LOG_INFO, "-- MARK --");
		t_last = t_now;
	}
}

void doflush(void *arg)
{
	struct filed *f;

	SIMPLEQ_FOREACH(f, &fhead, f_link) {
		if (f->f_type == F_FORW_UNKN) {
			forw_lookup(f);
			if (f->f_type != F_FORW)
				continue;
		}

		if (f->f_prevcount && timer_now() >= REPEATTIME(f)) {
			logit("flush %s: repeated %lu times, %d sec.\n",
			      TypeNames[f->f_type], f->f_prevcount,
			      repeatinterval[f->f_repeatcount]);
			fprintlog_successive(f, 0);
			BACKOFF(f);
		}
	}
}

void debug_switch(int signo)
{
	logit("Switching debug %s ...\n", debugging_on == 0 ? "on" : "off");
	debugging_on = (debugging_on == 0) ? 1 : 0;
}

/*
 * Called by die() and init()
 */
static void close_open_log_files(void)
{
	struct filed *f = NULL, *next = NULL;

	SIMPLEQ_FOREACH_SAFE(f, &fhead, f_link, next) {
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog_successive(f, 0);

		switch (f->f_type) {
		case F_FILE:
		case F_TTY:
		case F_CONSOLE:
		case F_PIPE:
			if (f->f_file >= 0)
				(void)close(f->f_file);
			break;

		case F_FORW:
			if (f->f_un.f_forw.f_addr) {
				freeaddrinfo(f->f_un.f_forw.f_addr);
				f->f_un.f_forw.f_addr = NULL;
			}
			break;
		}

		free(f);
	}
}

void die(int signo)
{
	struct peer *pe = NULL, *next = NULL;

	if (signo) {
		logit("syslogd: exiting on signal %d\n", signo);
		flog(LOG_SYSLOG | LOG_INFO, "exiting on signal %d", signo);
	}

	/*
	 * Stop all active timers
	 */
	timer_exit();

	/*
	 * Close all open log files.
	 */
	close_open_log_files();

	/*
	 * Close all UNIX and inet sockets
	 */
	SIMPLEQ_FOREACH_SAFE(pe, &pqueue, pe_link, next) {
		for (size_t i = 0; i < pe->pe_socknum; i++) {
			logit("Closing socket %d ...\n", pe->pe_sock[i]);
			socket_close(pe->pe_sock[i]);
		}
		free(pe);
	}

	kern_console_on();

	exit(0);
}

/*
 * fork off and become a daemon, but wait for the child to come online
 * before returning to the parent, or we get disk thrashing at boot etc.
 * Set a timer so we don't hang forever if it wedges.
 */
static int waitdaemon(int maxwait)
{
#ifdef HAVE_FORK
	struct sigaction sa;
	pid_t pid, childpid;
	int status;
	int fd;

	childpid = fork();
	switch (childpid) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		memset(&sa, 0, sizeof(sa));
		sa.sa_flags = SA_RESETHAND;
		sa.sa_handler = timedout;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGALRM, &sa, NULL);

		/* Send SIGALRM to parent process */
		alarm(maxwait);

		while ((pid = wait3(&status, 0, NULL)) != -1) {
			if (WIFEXITED(status))
				errx(1, "child pid %d exited with return code %d",
					pid, WEXITSTATUS(status));
			if (WIFSIGNALED(status))
				errx(1, "child pid %d exited on signal %d%s",
					pid, WTERMSIG(status),
					WCOREDUMP(status) ? " (core dumped)" :
					"");
			if (pid == childpid)	/* it's gone... */
				break;
		}
		exit(0);
	}

	if (setsid() == -1)
		return -1;

	(void)chdir("/");
	fd = open(_PATH_DEVNULL, O_RDWR, 0);
	if (fd != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		(void)close(fd);
	}

#endif /* HAVE_FORK */
	return getppid();
}

/*
 * We get a SIGALRM from the child when it's running and finished doing it's
 * fsync()'s or O_SYNC writes for all the boot messages.
 *
 * We also get a signal from the kernel if the timer expires, so check to
 * see what happened.
 */
static void timedout(int signo)
{
	int left;

	left = alarm(0);
	if (left == 0)
		errx(1, "timed out waiting for child");

	_exit(0);
}

/* Create fallback .conf with err+panic sent to console */
static FILE *cftemp(void)
{
	FILE *fp;
#ifdef O_TMPFILE
	mode_t oldmask;
	int fd;

	oldmask = umask(0077);
	fd = open(_PATH_TMP, O_TMPFILE | O_RDWR | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
	umask(oldmask);
	if (-1 == fd)
		return NULL;

	fp = fdopen(fd, "w+");
#else
	fp = tmpfile();
#endif
	if (!fp)
		return NULL;

	fprintf(fp, "*.err\t%s\n", _PATH_CONSOLE);
	fprintf(fp, "*.panic\t*\n");

	rewind(fp);
	return fp;
}

/* Set up signal callbacks, only done once in main() */
static void signal_init(void)
{
	struct sigaction sa;
#define SIGNAL(signo, cb)				\
	sa.sa_handler = cb;				\
	if (sigaction(signo, &sa, NULL)) {		\
		warn("sigaction(%s)", xstr(signo));	\
		return;					\
	}

	/* restart syscalls and allow signals in signal handlers */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART | SA_NODEFER;
	sigemptyset(&sa.sa_mask);

	SIGNAL(SIGTERM, die);
	SIGNAL(SIGINT,  Debug ? die : SIG_IGN);
	SIGNAL(SIGQUIT, Debug ? die : SIG_IGN);
	SIGNAL(SIGUSR1, Debug ? debug_switch : SIG_IGN);
	SIGNAL(SIGUSR2, signal_rotate);
#ifdef SIGXFSZ
	SIGNAL(SIGXFSZ, SIG_IGN);
#endif
	SIGNAL(SIGHUP,  reload);
	SIGNAL(SIGCHLD, reapchild);
}

static void boot_time_init(void)
{
#if defined(__linux__) || defined(__NuttX__)
	struct sysinfo si;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) == -1) {
		tv.tv_sec  = time(NULL);
		tv.tv_usec = 0;
	}
	sysinfo(&si);
	boot_time = tv.tv_sec - si.uptime;
#endif
}

/*
 *  INIT -- Initialize syslogd from configuration table
 */
static void init(void)
{
	struct notifiers newn = SIMPLEQ_HEAD_INITIALIZER(newn);
	struct files newf = SIMPLEQ_HEAD_INITIALIZER(newf);
	struct filed *f;
	struct peer *pe;
	FILE *fp;
	char *p;

	/* Set up timer framework */
	if (timer_init())
		err(1, "Failed initializing internal timers");

	/* Get hostname */
	(void)gethostname(LocalHostName, sizeof(LocalHostName));
	LocalDomain = emptystring;
	if ((p = strchr(LocalHostName, '.'))) {
		*p++ = '\0';
		LocalDomain = p;
	} else {
		struct hostent *hent;

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
	for (p = (char *)LocalDomain; *p; p++) {
		if (isupper(*p))
			*p = tolower(*p);
	}

	/*
	 * Load / reload timezone data (in case it changed)
	 */
	tzset();

	/*
	 * Read configuration file(s)
	 */
	fp = fopen(ConfFile, "r");
	if (!fp) {
		logit("Cannot open %s: %s\n", ConfFile, strerror(errno));

		fp = cftemp();
		if (!fp) {
			logit("Cannot even create a tempfile: %s\n", strerror(errno));
			return;
		}
	}

	if (cfparse(fp, &newf, &newn)) {
		fclose(fp);
		return;
	}
	fclose(fp);

	/*
	 * Close all open log files.
	 */
	close_open_log_files();

	fhead = newf;

	/*
	 * Free all notifiers
	 */
	notifier_free_all();

	nothead = newn;

	/*
	 * Open or close sockets for local and remote communication
	 */
	SIMPLEQ_FOREACH(pe, &pqueue, pe_link) {
		if (pe->pe_name && pe->pe_name[0] == '/') {
			create_unix_socket(pe);
		} else {
			for (size_t i = 0; i < pe->pe_socknum; i++)
				socket_close(pe->pe_sock[i]);
			pe->pe_socknum = 0;

			if (SecureMode < 2)
				create_inet_socket(pe);
		}
	}

	Initialized = 1;

	if (Debug) {
		if (!SIMPLEQ_EMPTY(&nothead)) {
			struct notifier *np;

			SIMPLEQ_FOREACH(np, &nothead, n_link)
				printf("notify %s\n", np->n_program);
			printf("\n");
		}

		SIMPLEQ_FOREACH(f, &fhead, f_link) {
			if (f->f_type == F_UNUSED)
				continue;

			for (int i = 0; i <= LOG_NFACILITIES; i++)
				if (f->f_pmask[i] == INTERNAL_INVPRI)
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
				printf("%s:%s", f->f_un.f_forw.f_hname, f->f_un.f_forw.f_serv);
				break;

			case F_USERS:
				for (int i = 0; i < MAXUNAMES && *f->f_un.f_uname[i]; i++)
					printf("%s%s", i > 0 ? ", " : "", f->f_un.f_uname[i]);
				break;
			}

			if (f->f_flags & RFC5424)
				printf("\t;RFC5424");
			else if (f->f_flags & RFC3164)
				printf("\t;RFC3164");
			else
				printf("\t;BSD");
			if (f->f_rotatesz > 0)
				printf(",rotate=%d:%d", f->f_rotatesz, f->f_rotatecount);
			printf("\n");
		}
	}

	flog(LOG_SYSLOG | LOG_INFO, "syslogd v" VERSION ": restart.");
	logit("syslogd: restarted.\n");
}

static void cfrot(char *ptr, struct filed *f)
{
	char *c;
	int sz = 0, cnt = 0;

	c = strchr(ptr, ':');
	if (c) {
		*c++ = 0;
		cnt = atoi(c);
	}

	sz = strtobytes(ptr);
	if (sz > 0 && cnt > 0) {
		logit("Set rotate size %d bytes, %d rotations\n", sz, cnt);
		f->f_rotatecount = cnt;
		f->f_rotatesz = sz;
	}
}

static int cfopt(char **ptr, const char *opt)
{
	size_t len;

	len = strlen(opt);
	if (!strncasecmp(*ptr, opt, len)) {
		*ptr += len;
		return 1;
	}

	return 0;
}

/*
 * Option processing
 */
static void cfopts(char *ptr, struct filed *f)
{
	char *opt;

	/* First locate any whitespace between action and option */
	ptr = strpbrk(ptr, "\t ;");
	if (!ptr)
		return;

	/* Insert NUL character to terminate file/host names */
	if (*ptr != ';')
		*ptr++ = 0;

	opt = strtok(ptr, ";");
	if (!opt)
		return;

	while (opt) {
		if (cfopt(&opt, "RFC5424")) {
			f->f_flags |=  RFC5424;
			f->f_flags &= ~RFC3164;
		} else if (cfopt(&opt, "RFC3164")) {
			f->f_flags &= ~RFC5424;
			f->f_flags |=  RFC3164;
		} else if (cfopt(&opt, "rotate="))
			cfrot(opt, f);
		else
			cfrot(ptr, f); /* Compat v1.6 syntax */

		opt = strtok(NULL, ",");
	}
}

/*
 * Crack a configuration file line
 */
static struct filed *cfline(char *line)
{
	struct filed *f;
	char buf[MAXLINE];
	char *p, *q, *bp;
	int ignorepri = 0;
	int singlpri = 0;
	int syncfile, pri;
	int i, i2;

	logit("cfline[%s]\n", line);

	f = calloc(1, sizeof(*f));
	if (!f) {
		ERR("Cannot allocate memory for log file");
		return NULL;
	}

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
			pri = decode(&buf[1], prioritynames);
		} else {
			singlpri = 0;
			pri = decode(buf, prioritynames);
		}

		if (pri < 0) {
			ERRX("unknown priority name \"%s\"", buf);
			free(f);

			return NULL;
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
							f->f_pmask[i] = INTERNAL_ALLPRI;
						else
							f->f_pmask[i] = INTERNAL_INVPRI;
					} else if (singlpri) {
						if (ignorepri)
							f->f_pmask[i] &= ~(1 << pri);
						else
							f->f_pmask[i] |= (1 << pri);
					} else {
						if (pri == INTERNAL_ALLPRI) {
							if (ignorepri)
								f->f_pmask[i] = INTERNAL_INVPRI;
							else
								f->f_pmask[i] = INTERNAL_ALLPRI;
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
				i = decode(buf, facilitynames);
				if (i < 0) {
					ERR("unknown facility name \"%s\"", buf);
					free(f);

					return NULL;
				}

				if (pri == INTERNAL_NOPRI) {
					if (ignorepri)
						f->f_pmask[i >> 3] = INTERNAL_ALLPRI;
					else
						f->f_pmask[i >> 3] = INTERNAL_INVPRI;
				} else if (singlpri) {
					if (ignorepri)
						f->f_pmask[i >> 3] &= ~(1 << pri);
					else
						f->f_pmask[i >> 3] |= (1 << pri);
				} else {
					if (pri == INTERNAL_ALLPRI) {
						if (ignorepri)
							f->f_pmask[i >> 3] = INTERNAL_INVPRI;
						else
							f->f_pmask[i >> 3] = INTERNAL_ALLPRI;
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
		cfopts(p, f);

		bp = strchr(++p, ':');
		if (bp)
			*bp++ = 0;
		else
			bp = "syslog"; /* default: 514/udp */

		strlcpy(f->f_un.f_forw.f_hname, p, sizeof(f->f_un.f_forw.f_hname));
		strlcpy(f->f_un.f_forw.f_serv, bp, sizeof(f->f_un.f_forw.f_serv));
		logit("forwarding host: '%s:%s'\n", p, bp);
		forw_lookup(f);
		break;

	case '|':
	case '/':
		cfopts(p, f);

		strlcpy(f->f_un.f_fname, p, sizeof(f->f_un.f_fname));
		logit("filename: '%s'\n", p); /*ASP*/
		if (syncfile)
			f->f_flags |= SYNC_FILE;
		if (*p == '|') {
			f->f_file = open(++p, O_RDWR | O_NONBLOCK | O_NOCTTY);
			f->f_type = F_PIPE;
		} else {
			f->f_file = open(p, O_CREATE | O_NONBLOCK | O_NOCTTY, 0644);
			f->f_type = F_FILE;
		}

		if (f->f_file < 0) {
			f->f_file = -1;
			ERR("Error opening log file: %s", p);
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
		logit("users: ");
		i = 0;
		q = strtok(p, ",");
		while (q && i < MAXUNAMES) {
			logit("%s ", q);
			strlcpy(f->f_un.f_uname[i++], q, sizeof(f->f_un.f_uname[0]));
			q = strtok(NULL, ",");
		}
		logit("\n");
		f->f_type = F_USERS;
		break;
	}

	/* Set default log format, unless format was already specified */
	switch (f->f_type) {
	case F_FORW:
	case F_FORW_UNKN:
		/* Remote syslog defaults to BSD style, i.e. no timestamp or hostname */
		break;

	case F_WALL:
	case F_USERS:
		/* Currently requires RFC3164 */
		f->f_flags &= ~RFC5424;
		f->f_flags |= RFC3164;
		break;

	case F_FILE:
		/* default rotate from command line */
		if (f->f_rotatesz == 0) {
			f->f_rotatecount = RotateCnt;
			f->f_rotatesz = RotateSz;
		}
		/* fallthrough */

	default:
		/* All other targets default to RFC3164 */
		if (f->f_flags & (RFC3164 | RFC5424))
			break;

		f->f_flags |= RFC3164;
		break;
	}

	if (f->f_flags & (RFC3164 | RFC5424))
		logit("%s format enabled\n", (f->f_flags & RFC3164) ? "RFC3164" : "RFC5424");
	else
		logit("BSD format enabled\n");

	return f;
}

/*
 * Find matching cfkey and modify cline to the argument.
 * Note, the key '=' value separator is optional.
 */
const struct cfkey *cfkey_match(char *cline)
{
	size_t i;

	for (i = 0; i < NELEMS(cfkey); i++) {
		const struct cfkey *cfk = &cfkey[i];
		size_t len = strlen(cfk->key);
		char *p;

		if (strncmp(cline, cfk->key, len))
			continue;

		p = &cline[len];
		while (*p && isspace(*p))
			p++;
		if (*p == '=')
			p++;
		while (*p && isspace(*p))
			p++;

		if (cfk->var)
			*cfk->var = strdup(p);
		else
			memmove(cline, p, strlen(p) + 1);

		return cfk;
	}

	return NULL;
}

/*
 * Parse .conf file and append to list
 */
static int cfparse(FILE *fp, struct files *newf, struct notifiers *newn)
{
	const struct cfkey *cfk;
	struct filed *f;
	char  cbuf[BUFSIZ];
	char *cline;
	char *p;

	if (!fp)
		return 1;

	/*
	 *  Foreach line in the conf table, open that file.
	 */
	cline = cbuf;
	while (fgets(cline, sizeof(cbuf) - (cline - cbuf), fp) != NULL) {
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

		if (!strncmp(cline, "include", 7)) {
			glob_t gl;

			p = &cline[7];
			while (*p && isspace(*p))
				p++;

			logit("Searching for %s ...\n", p);
			if (glob(p, GLOB_NOSORT, NULL, &gl))
				logit("No files match %s\n", p);

			for (size_t i = 0; i < gl.gl_pathc; i++) {
				FILE *fpi;

				logit("Opening %s ...\n", gl.gl_pathv[i]);
				fpi = fopen(gl.gl_pathv[i], "r");
				if (!fpi) {
					logit("Failed opening %s: %s\n",
					      gl.gl_pathv[i], strerror(errno));
					continue;
				}

				logit("Parsing %s ...\n", gl.gl_pathv[i]);
				cfparse(fpi, newf, newn);
				fclose(fpi);
			}
			globfree(&gl);
			continue;
		}

		cfk = cfkey_match(cline);
		if (cfk) {
			if (!strcmp(cfk->key, "notify"))
				notifier_add(newn, cline);
			continue;
		}

		f = cfline(cline);
		if (!f)
			continue;

		SIMPLEQ_INSERT_TAIL(newf, f, f_link);
	}

	if (secure_str) {
		int val;

		val = atoi(secure_str);
		if (val < 0 || val > 2)
			logit("Invalid value to secure_mode = %s\n", secure_str);
		else
			secure_mode = val;

		free(secure_str);
		secure_str = NULL;
	}

	return 0;
}

/*
 *  Decode a symbolic name to a numeric value
 */
int decode(char *name, struct _code *codetab)
{
	struct _code *c;
	char *p;
	char buf[80];

	logit("symbolic name: %s", name);
	if (isdigit(*name)) {
		logit("\n");
		return atoi(name);
	}

	strlcpy(buf, name, sizeof(buf));
	for (p = buf; *p; p++) {
		if (isupper(*p))
			*p = tolower(*p);
	}

	for (c = codetab; c->c_name; c++) {
		if (!strcmp(buf, c->c_name)) {
			logit(" ==> %d\n", c->c_val);
			return c->c_val;
		}
	}

	return -1;
}

/*
 * Add `s' to the list of allowable peer addresses to accept messages
 * from.
 *
 * `s' is a string in the form:
 *
 *    [*]domainname[:{servicename|portnumber|*}]
 *
 * or
 *
 *    netaddr/maskbits[:{servicename|portnumber|*}]
 *
 * Returns -1 on error, 0 if the argument was valid.
 */
static int allowaddr(char *s)
{
	char *cp1, *cp2;
	struct allowedpeer *ap;
	struct servent *se;
	int masklen = -1;
	struct addrinfo hints, *res = NULL;
	in_addr_t *addrp, *maskp;
	uint32_t *addr6p, *mask6p;

	ap = calloc(1, sizeof(*ap));
	if (ap == NULL)
		err(1, "malloc failed");

	if (*s != '[' || (cp1 = strchr(s + 1, ']')) == NULL)
		cp1 = s;
	if ((cp1 = strrchr(cp1, ':'))) {
		/* service/port provided */
		*cp1++ = '\0';
		if (strlen(cp1) == 1 && *cp1 == '*')
			/* any port allowed */
			ap->port = 0;
		else if ((se = getservbyname(cp1, "udp"))) {
			ap->port = ntohs(se->s_port);
		} else {
			ap->port = strtol(cp1, &cp2, 0);
			/* port not numeric */
			if (*cp2 != '\0')
				goto err;
		}
	} else {
		if ((se = getservbyname("syslog", "udp")))
			ap->port = ntohs(se->s_port);
		else
			/* sanity, should not happen */
			ap->port = 514;
	}

	if ((cp1 = strchr(s, '/')) != NULL &&
	    strspn(cp1 + 1, "0123456789") == strlen(cp1 + 1)) {
		*cp1 = '\0';
		if ((masklen = atoi(cp1 + 1)) < 0)
			goto err;
	}

	if (*s == '[') {
		cp2 = s + strlen(s) - 1;
		if (*cp2 == ']') {
			++s;
			*cp2 = '\0';
		} else {
			cp2 = NULL;
		}
	} else {
		cp2 = NULL;
	}

	hints = (struct addrinfo){
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_PASSIVE | AI_NUMERICHOST
	};
	if (getaddrinfo(s, NULL, &hints, &res) == 0) {
		ap->isnumeric = 1;
		memcpy(&ap->a_addr, res->ai_addr, res->ai_addrlen);
		ap->a_mask = (struct sockaddr_storage){
			.ss_family = res->ai_family,
#ifdef HAVE_SA_LEN
			.ss_len = res->ai_addrlen
#endif
		};
		switch (res->ai_family) {
		case AF_INET:
			maskp = &sstosin(&ap->a_mask)->sin_addr.s_addr;
			addrp = &sstosin(&ap->a_addr)->sin_addr.s_addr;
			if (masklen < 0) {
				/* use default netmask */
				if (IN_CLASSA(ntohl(*addrp)))
					*maskp = htonl(IN_CLASSA_NET);
				else if (IN_CLASSB(ntohl(*addrp)))
					*maskp = htonl(IN_CLASSB_NET);
				else
					*maskp = htonl(IN_CLASSC_NET);
			} else if (masklen == 0) {
				*maskp = 0;
			} else if (masklen <= 32) {
				/* convert masklen to netmask */
				*maskp = htonl(~((1 << (32 - masklen)) - 1));
			} else {
				goto err;
			}
			/* Lose any host bits in the network number. */
			*addrp &= *maskp;
			break;

		case AF_INET6:
			if (masklen > 128)
				goto err;

			if (masklen < 0)
				masklen = 128;
			mask6p = (uint32_t *)&sstosin6(&ap->a_mask)->sin6_addr.s6_addr32[0];
			addr6p = (uint32_t *)&sstosin6(&ap->a_addr)->sin6_addr.s6_addr32[0];
			/* convert masklen to netmask */
			while (masklen > 0) {
				if (masklen < 32) {
					*mask6p =
					    htonl(~(0xffffffff >> masklen));
					*addr6p &= *mask6p;
					break;
				} else {
					*mask6p++ = 0xffffffff;
					addr6p++;
					masklen -= 32;
				}
			}
			break;

		default:
			goto err;
		}
		freeaddrinfo(res);
	} else {
		/* arg `s' is domain name */
		ap->isnumeric = 0;
		ap->a_name = s;
		if (cp1)
			*cp1 = '/';
		if (cp2) {
			*cp2 = ']';
			--s;
		}
	}
	SIMPLEQ_INSERT_TAIL(&aphead, ap, next);

	if (Debug) {
		char ip[NI_MAXHOST];

		printf("allowaddr: rule ");
		if (ap->isnumeric) {
			socklen_t len;
#ifdef HAVE_SA_LEN
			len = (sstosa(&ap->a_addr))->sa_len;
#else
			if (ap->a_addr.ss_family == AF_INET)
				len = sizeof(struct sockaddr_in);
			else
				len = sizeof(struct sockaddr_in6);
#endif
			printf("numeric, ");
			getnameinfo(sstosa(&ap->a_addr), len,
				    ip, sizeof ip, NULL, 0, NI_NUMERICHOST);
			printf("addr = %s, ", ip);
			getnameinfo(sstosa(&ap->a_mask), len,
				    ip, sizeof ip, NULL, 0, NI_NUMERICHOST);
			printf("mask = %s; ", ip);
		} else {
			printf("domainname = %s; ", ap->a_name);
		}
		printf("port = %d\n", ap->port);
	}

	return 0;
err:
	if (res != NULL)
		freeaddrinfo(res);
	free(ap);
	return -1;
}

/*
 * Validate that the remote peer has permission to log to us.
 */
static int validate(struct sockaddr *sa, const char *hname)
{
	char name[NI_MAXHOST], ip[NI_MAXHOST], port[NI_MAXSERV];
	struct allowedpeer *ap;
	struct sockaddr_in *sin4, *a4p = NULL, *m4p = NULL;
	struct sockaddr_in6 *sin6, *a6p = NULL, *m6p = NULL;
	struct addrinfo hints, *res;
	socklen_t len;
	u_short sport;
	int i, num = 0;

	SIMPLEQ_FOREACH(ap, &aphead, next)
		num++;

	logit("# of validation rule: %d\n", num);
	if (num == 0)
		/* traditional behaviour, allow everything */
		return 1;

	(void)strlcpy(name, hname, sizeof(name));
	hints = (struct addrinfo){
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_PASSIVE | AI_NUMERICHOST
	};
	if (getaddrinfo(name, NULL, &hints, &res) == 0)
		freeaddrinfo(res);
	else if (strchr(name, '.') == NULL) {
		strlcat(name, ".", sizeof name);
		strlcat(name, LocalDomain, sizeof name);
	}

#ifdef HAVE_SA_LEN
	len = sa->sa_len;
#else
	if (sa->sa_family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);
#endif
	if (getnameinfo(sa, len, ip, sizeof(ip), port, sizeof(port),
			NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		return 0;	/* for safety, should not occur */

	logit("validate: dgram from IP %s, port %s, name %s;\n", ip, port, name);
	sport = atoi(port);

	/* now, walk down the list */
	i = 0;
	SIMPLEQ_FOREACH(ap, &aphead, next) {
		i++;
		if (ap->port != 0 && ap->port != sport) {
			logit("rejected in rule %d due to port mismatch.\n", i);
			continue;
		}

		if (ap->isnumeric) {
			if (ap->a_addr.ss_family != sa->sa_family) {
				logit("rejected in rule %d due to address family mismatch.\n", i);
				continue;
			} else if (ap->a_addr.ss_family == AF_INET) {
				sin4 = satosin(sa);
				a4p = satosin(&ap->a_addr);
				m4p = satosin(&ap->a_mask);
				if ((sin4->sin_addr.s_addr & m4p->sin_addr.s_addr)
				    != a4p->sin_addr.s_addr) {
					logit("rejected in rule %d due to IP mismatch.\n", i);
					continue;
				}
			} else if (ap->a_addr.ss_family == AF_INET6) {
				sin6 = satosin6(sa);
				a6p = satosin6(&ap->a_addr);
				m6p = satosin6(&ap->a_mask);
				if (a6p->sin6_scope_id != 0 &&
				    sin6->sin6_scope_id != a6p->sin6_scope_id) {
					logit("rejected in rule %d due to scope mismatch.\n", i);
					continue;
				}
				if (!IN6_ARE_MASKED_ADDR_EQUAL(&sin6->sin6_addr,
				    &a6p->sin6_addr, &m6p->sin6_addr)) {
					logit("rejected in rule %d due to IP mismatch.\n", i);
					continue;
				}
			} else
				continue;
		} else {
			if (fnmatch(ap->a_name, name, FNM_NOESCAPE) ==
			    FNM_NOMATCH) {
				logit("rejected in rule %d due to name mismatch.\n", i);
				continue;
			}
		}

		logit("accepted in rule %d.\n", i);
		return 1;	/* hooray! */
	}

	return 0;
}

static void logit(char *fmt, ...)
{
	va_list ap;

	if (!debugging_on)
		return;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	fflush(stdout);
}

static void notifier_add(struct notifiers *newn, const char *program)
{
	while (*program && isspace(*program))
		++program;

	/* Check whether it is accessible, regardless of TOCTOU */
	if (!access(program, X_OK)) {
		struct notifier *np;

		np = calloc(1, sizeof(*np));
		if (!np) {
			ERR("Cannot allocate memory for a notify program");
			return;
		}
		np->n_program = strdup(program);
		if (!np->n_program) {
			free (np);
			ERR("Cannot allocate memory for a notify program");
			return;
		}
		SIMPLEQ_INSERT_TAIL(newn, np, n_link);
	} else
		logit("notify: non-existing, or not executable program\n");
}

static void notifier_invoke(const char *logfile)
{
	char *argv[3];
	int childpid;
	struct notifier *np;

	logit("notify: rotated %s, invoking hooks\n", logfile);

	SIMPLEQ_FOREACH(np, &nothead, n_link) {
		childpid = fork();

		switch (childpid) {
		case -1:
			ERR("Cannot start notifier %s", np->n_program);
			break;
		case 0:
			argv[0] = np->n_program;
			argv[1] = (char*)logfile;
			argv[2] = NULL;
			execv(argv[0], argv);
			_exit(1);
		default:
			logit("notify: forked child pid %d for %s\n",
				childpid, np->n_program);
			break;
		}
	}
}

static void notifier_free_all(void)
{
	struct notifier *np, *npnext;

	SIMPLEQ_FOREACH_SAFE(np, &nothead, n_link, npnext) {
		free(np->n_program);
		free(np);
	}
}

/*
 * The following function is resposible for handling a SIGHUP signal.  Since
 * we are now doing mallocs/free as part of init we had better not being
 * doing this during a signal handler.  Instead this function simply sets
 * a flag variable which will tell the main loop to go through a restart.
 */
void reload(int signo)
{
	restart++;
}

/*
 * SIGUSR2: forced rotation for so-configured files as soon as possible.
 */
static void signal_rotate(int sig)
{
	(void)sig;
	rotate_signal++;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
