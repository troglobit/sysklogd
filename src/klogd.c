/*-
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * klogd.c - main program for Linux kernel log daemon.
 *
 * Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include "compat.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "klogd.h"
#include "ksyms.h"
#include <paths.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>

#define __LIBRARY__
#include <linux/unistd.h>
#include <sys/klog.h>
#define ksyslog klogctl

#define LOG_BUFFER_SIZE 4096
#define LOG_LINE_LENGTH 1000

static char *PidFile = _PATH_VARRUN "klogd.pid";

static int kmsg;
static int change_state      = 0;
static int terminate         = 0;
static int caught_TSTP       = 0;
static int reload_symbols    = 0;
static int console_log_level = -1;

static int use_syscall   = 0;
static int one_shot      = 0;
static int symbol_lookup = 1;
static int no_fork       = 0; /* don't fork - don't run in daemon mode */

static char *symfile = NULL;
static char log_buffer[LOG_BUFFER_SIZE];

static FILE *output_file = NULL;

static enum LOGSRC { none, proc, kernel } logsrc;

int debugging     = 0;
int symbols_twice = 0;

/* Function prototypes. */
extern int         ksyslog(int type, char *buf, int len);
static void        CloseLogSrc(void);
extern void        restart(int sig);
extern void        stop_logging(int sig);
extern void        stop_daemon(int sig);
extern void        reload_daemon(int sig);
static void        Terminate(void);
static void        ReloadSymbols(void);
static void        ChangeLogging(void);
static enum LOGSRC GetKernelLogSrc(void);
static void        LogLine(char *ptr, int len);
static void        LogKernelLine(void);
static void        LogProcLine(void);
extern int         main(int argc, char *argv[]);

static void CloseLogSrc(void)
{
	/* Shutdown the log sources. */
	switch (logsrc) {
	case kernel:
		ksyslog(0, 0, 0);
		Syslog(LOG_INFO, "Kernel logging (ksyslog) stopped.");
		break;

	case proc:
		close(kmsg);
		Syslog(LOG_INFO, "Kernel logging (proc) stopped.");
		break;

	case none:
		break;
	}

	if (output_file != NULL)
		fflush(output_file);
}

/*
 * Signal handler to terminate the parent process.
 */
void doexit(int signo)
{
	exit(0);
}

void restart(int signo)
{
	change_state = 1;
	caught_TSTP = 0;
}

void stop_logging(int signo)
{
	change_state = 1;
	caught_TSTP = 1;
}

void stop_daemon(int signo)
{
	Terminate();
}

void reload_daemon(int signo)
{
	change_state = 1;
	reload_symbols = 1;

	if (signo == SIGUSR2)
		++reload_symbols;
}

static void Terminate(void)
{
	CloseLogSrc();
	Syslog(LOG_INFO, "Kernel log daemon terminating.");
	sleep(1);

	if (output_file != NULL)
		fclose(output_file);
	closelog();

	exit(1);
}

static void ReloadSymbols(void)
{
	if (symbol_lookup) {
		if (reload_symbols > 1)
			InitKsyms(symfile);
		InitMsyms();
	}
	reload_symbols = change_state = 0;
}

static void ChangeLogging(void)
{
	/* Terminate kernel logging. */
	if (terminate == 1)
		Terminate();

	/* Indicate that something is happening. */
	Syslog(LOG_INFO, "klogd v%s, ---------- state change ----------\n",
	       PACKAGE_VERSION);

	/* Reload symbols. */
	if (reload_symbols > 0) {
		ReloadSymbols();
		return;
	}

	/* Stop kernel logging. */
	if (caught_TSTP == 1) {
		CloseLogSrc();
		logsrc = none;
		change_state = 0;
		return;
	}

	/*
	 * The rest of this function is responsible for restarting
	 * kernel logging after it was stopped.
	 *
	 * In the following section we make a decision based on the
	 * kernel log state as to what is causing us to restart.  Somewhat
	 * groady but it keeps us from creating another static variable.
	 */
	if (logsrc != none) {
		Syslog(LOG_INFO, "Kernel logging re-started after SIGSTOP.");
		change_state = 0;
		return;
	}

	/* Restart logging. */
	logsrc = GetKernelLogSrc();
	change_state = 0;
}

static enum LOGSRC GetKernelLogSrc(void)
{
	struct stat sb;

	/* Set level of kernel console messaging.. */
	if ((console_log_level != -1) && (ksyslog(8, NULL, console_log_level) < 0) &&
	    (errno == EINVAL)) {
		/*
		 * An invalid arguement error probably indicates that
		 * a pre-0.14 kernel is being run.  At this point we
		 * issue an error message and simply shut-off console
		 * logging completely.
		 */
		Syslog(LOG_WARNING, "Cannot set console log level - disabling "
		                    "console output.");
	}

	/*
	 * First do a stat to determine whether or not the proc based
	 * file system is available to get kernel messages from.
	 */
	if (use_syscall ||
	    ((stat(_PATH_KLOG, &sb) < 0) && (errno == ENOENT))) {
		/* Initialize kernel logging. */
		ksyslog(1, NULL, 0);
		Syslog(LOG_INFO, "klogd v%s, log source = ksyslog "
		                 "started.",
		       PACKAGE_VERSION);
		return kernel;
	}

	if ((kmsg = open(_PATH_KLOG, O_RDONLY)) < 0) {
		fprintf(stderr, "klogd: Cannot open proc file system, "
		                "%d - %s.\n",
		        errno, strerror(errno));
		ksyslog(7, NULL, 0);
		exit(1);
	}

	Syslog(LOG_INFO, "klogd v%s, log source = %s started.",
	       VERSION, _PATH_KLOG);

	return proc;
}

extern void Syslog(int priority, char *fmt, ...)

{
	va_list ap;
	char *argl;

	if (debugging) {
		fputs("Logging line:\n", stderr);
		fprintf(stderr, "\tLine: %s\n", fmt);
		fprintf(stderr, "\tPriority: %d\n", priority);
	}

	/* Handle output to a file. */
	if (output_file != NULL) {
		va_start(ap, fmt);
		vfprintf(output_file, fmt, ap);
		va_end(ap);
		fputc('\n', output_file);
		fflush(output_file);
		if (!one_shot)
			fsync(fileno(output_file));
		return;
	}

	/* Output using syslog. */
	if (!strcmp(fmt, "%s")) {
		va_start(ap, fmt);
		argl = va_arg(ap, char *);
		if (argl[0] == '<' && argl[1] && argl[2] == '>') {
			switch (argl[1]) {
			case '0':
				priority = LOG_EMERG;
				break;
			case '1':
				priority = LOG_ALERT;
				break;
			case '2':
				priority = LOG_CRIT;
				break;
			case '3':
				priority = LOG_ERR;
				break;
			case '4':
				priority = LOG_WARNING;
				break;
			case '5':
				priority = LOG_NOTICE;
				break;
			case '6':
				priority = LOG_INFO;
				break;
			case '7':
			default:
				priority = LOG_DEBUG;
			}
			argl += 3;
		}
		syslog(priority, fmt, argl);
		va_end(ap);
		return;
	}

	va_start(ap, fmt);
	vsyslog(priority, fmt, ap);
	va_end(ap);
}

/*
 *     Copy characters from ptr to line until a char in the delim
 *     string is encountered or until min( space, len ) chars have
 *     been copied.
 *
 *     Returns the actual number of chars copied.
 */
static int copyin(char *line, int space,
                  const char *ptr, int len,
                  const char *delim)
{
	int i;
	int count;

	count = len < space ? len : space;

	for (i = 0; i < count && !strchr(delim, *ptr); i++)
		*line++ = *ptr++;

	return i;
}

/*
 * Messages are separated by "\n".  Messages longer than
 * LOG_LINE_LENGTH are broken up.
 *
 * Kernel symbols show up in the input buffer as : "[<aaaaaa>]",
 * where "aaaaaa" is the address.  These are replaced with
 * "[symbolname+offset/size]" in the output line - symbolname,
 * offset, and size come from the kernel symbol table.
 *
 * If a kernel symbol happens to fall at the end of a message close
 * in length to LOG_LINE_LENGTH, the symbol will not be expanded.
 * (This should never happen, since the kernel should never generate
 * messages that long.
 *
 * To preserve the original addresses, lines containing kernel symbols
 * are output twice.  Once with the symbols converted and again with the
 * original text.  Just in case somebody wants to run their own Oops
 * analysis on the syslog, e.g. ksymoops.
 */
static void LogLine(char *ptr, int len)
{
	enum parse_state_enum {
		PARSING_TEXT,
		PARSING_SYMSTART, /* at < */
		PARSING_SYMBOL,
		PARSING_SYMEND /* at ] */
	};

	static char line_buff[LOG_LINE_LENGTH];

	static char *                line = line_buff;
	static enum parse_state_enum parse_state = PARSING_TEXT;
	static int                   space = sizeof(line_buff) - 1;

	static char *sym_start; /* points at the '<' of a symbol */

	int   delta = 0;              /* number of chars copied        */
	int   symbols_expanded = 0;   /* 1 if symbols were expanded */
	int   skip_symbol_lookup = 0; /* skip symbol lookup on this pass */
	char *save_ptr = ptr;         /* save start of input line */
	int   save_len = len;         /* save length at start of input line */

	while (len > 0) {
		if (space == 0) { /* line buffer is full */
			/*
			** Line too long.  Start a new line.
			*/
			*line = 0; /* force null terminator */

			if (debugging) {
				fputs("Line buffer full:\n", stderr);
				fprintf(stderr, "\tLine: %s\n", line);
			}

			Syslog(LOG_INFO, "%s", line_buff);
			line = line_buff;
			space = sizeof(line_buff) - 1;
			parse_state = PARSING_TEXT;
			symbols_expanded = 0;
			skip_symbol_lookup = 0;
			save_ptr = ptr;
			save_len = len;
		}

		switch (parse_state) {
		case PARSING_TEXT:
			delta = copyin(line, space, ptr, len, "\n[");
			line += delta;
			ptr += delta;
			space -= delta;
			len -= delta;

			if (space == 0 || len == 0)
				break; /* full line_buff or end of input buffer */

			if (*ptr == '\0') { /* zero byte */
				ptr++; /* skip zero byte */
				space -= 1;
				len -= 1;

				break;
			}

			if (*ptr == '\n') { /* newline */
				ptr++; /* skip newline */
				space -= 1;
				len -= 1;

				*line = 0; /* force null terminator */
				Syslog(LOG_INFO, "%s", line_buff);
				line = line_buff;
				space = sizeof(line_buff) - 1;
				if (symbols_twice) {
					if (symbols_expanded) {
						/* reprint this line without symbol lookup */
						symbols_expanded = 0;
						skip_symbol_lookup = 1;
						ptr = save_ptr;
						len = save_len;
					} else {
						skip_symbol_lookup = 0;
						save_ptr = ptr;
						save_len = len;
					}
				}
				break;
			}
			if (*ptr == '[') { /* possible kernel symbol */
				*line++ = *ptr++;
				space -= 1;
				len -= 1;
				if (!skip_symbol_lookup)
					parse_state = PARSING_SYMSTART; /* at < */
				break;
			}
			break;

		case PARSING_SYMSTART:
			if (*ptr != '<') {
				parse_state = PARSING_TEXT; /* not a symbol */
				break;
			}

			/*
			** Save this character for now.  If this turns out to
			** be a valid symbol, this char will be replaced later.
			** If not, we'll just leave it there.
			*/
			sym_start = line; /* this will point at the '<' */

			*line++ = *ptr++;
			space -= 1;
			len -= 1;
			parse_state = PARSING_SYMBOL; /* symbol... */
			break;

		case PARSING_SYMBOL:
			delta = copyin(line, space, ptr, len, ">\n[");
			line += delta;
			ptr += delta;
			space -= delta;
			len -= delta;
			if (space == 0 || len == 0)
				break; /* full line_buff or end of input buffer */

			if (*ptr != '>') {
				parse_state = PARSING_TEXT;
				break;
			}

			*line++ = *ptr++; /* copy the '>' */
			space -= 1;
			len -= 1;

			parse_state = PARSING_SYMEND;
			break;

		case PARSING_SYMEND:
			if (*ptr != ']') {
				parse_state = PARSING_TEXT; /* not a symbol */
				break;
			}

			/*
			** It's really a symbol!  Replace address with the
			** symbol text.
			*/
			{
				unsigned long value;
				struct symbol sym;
				char *symbol;
				int sym_space;

				*(line - 1) = 0; /* null terminate the address string */
				value = strtoul(sym_start + 1, NULL, 16);
				*(line - 1) = '>'; /* put back delim */

				symbol = LookupSymbol(value, &sym);
				if (!symbol_lookup || symbol == NULL) {
					parse_state = PARSING_TEXT;
					break;
				}

				/*
				** verify there is room in the line buffer
				*/
				sym_space = space + (line - sym_start);
				if (sym_space < (int)strlen(symbol) + 30) { /*(30 should be overkill)*/
					parse_state = PARSING_TEXT; /* not enough space */
					break;
				}

				delta = sprintf(sym_start, "%s+0x%x/0x%02x]",
				                symbol, sym.offset, sym.size);

				space = sym_space + delta;
				line = sym_start + delta;
				symbols_expanded = 1;
			}
			ptr++;
			len--;
			parse_state = PARSING_TEXT;
			break;

		default: /* Can't get here! */
			parse_state = PARSING_TEXT;
			break;
		}
	}
}

static void LogKernelLine(void)
{
	int rdcnt;

	/*
	 * Zero-fill the log buffer.  This should cure a multitude of
	 * problems with klogd logging the tail end of the message buffer
	 * which will contain old messages.  Then read the kernel log
	 * messages into this fresh buffer.
	 */
	memset(log_buffer, 0, sizeof(log_buffer));
	if ((rdcnt = ksyslog(2, log_buffer, sizeof(log_buffer) - 1)) < 0) {
		if (errno == EINTR)
			return;

		fprintf(stderr,
			"klogd: Error return from sys_sycall: %d - %s\n",
		        errno, strerror(errno));
		return;
	}

	LogLine(log_buffer, rdcnt);
}

static void LogProcLine(void)
{
	int rdcnt;

	/*
	 * Zero-fill the log buffer.  This should cure a multitude of
	 * problems with klogd logging the tail end of the message buffer
	 * which will contain old messages.  Then read the kernel messages
	 * from the message pseudo-file into this fresh buffer.
	 */
	memset(log_buffer, 0, sizeof(log_buffer));
	if ((rdcnt = read(kmsg, log_buffer, sizeof(log_buffer) - 1)) < 0) {
		if (errno == EINTR)
			return;
		Syslog(LOG_ERR, "Cannot read proc file system: %d - %s.",
		       errno, strerror(errno));
		return;
	}

	LogLine(log_buffer, rdcnt);
}

int usage(int code)
{
	fprintf(stdout,
	        "Usage:\n"
	        "  klogd [-2diInopsvx?] [-c NUM] [-f FILE] [-k FILE]\n"
	        "\n"
	        "Options:\n"
	        "  -?        Show this help text\n"
	        "  -2        Print line twice if symbols are successfully expanded\n"
	        "  -c NUM    Set default log level of console messages to NUM (1-8)\n"
	        "  -d        Enable debug mode\n"
	        "  -f FILE   Log messages to FILE rather than the syslog facility\n"
	        "  -i        Signal klogd to reload kernel module symbols\n"
	        "  -I        Signal klogd to reload kernel module *and* static kernel symbols\n"
	        "  -k FILE   Location of kernel symbols (System.map), default: auto\n"
	        "  -n        Run in foreground, required when run from a modern init/supervisor\n"
	        "  -o        Run once, read kernel log messages and syslog them, then exit\n"
	        "  -p        Paranoia mode, forces klogd to reload all kernel symbols on Ooops\n"
	        "  -s        Force use of system call interface to kernel message buffers\n"
	        "  -v        Show program version and exit\n"
	        "  -x        Omit EIP translation, i.e. do not read System.map file\n"
	        "\n"
		"SIGUSR1 reloads kernel module symbols, SIGUSR2 reloads all kernel symbols.\n"
	        "\n"
	        "Bug report address: %s\n",
	        PACKAGE_BUGREPORT);
	exit(code);
}

int main(int argc, char *argv[])
{
	char *log_level = NULL;
	char *output = NULL;
	int use_output = 0;
	int ch;
	pid_t ppid = getpid();

	/* Parse the command-line. */
	while ((ch = getopt(argc, argv, "c:df:k:nopsvx2?")) != EOF) {
		switch (ch) {
		case '2': /* Print lines with symbols twice. */
			symbols_twice = 1;
			break;

		case 'c': /* Set console message level. */
			log_level = optarg;
			break;

		case 'd': /* Activity debug mode. */
			debugging = 1;
			break;

		case 'f': /* Define an output file. */
			output = optarg;
			use_output++;
			break;

		case 'k': /* Kernel symbol file. */
			symfile = optarg;
			break;

		case 'n': /* don't fork */
			no_fork++;
			break;

		case 'o': /* One-shot mode. */
			one_shot = 1;
			break;

		case 'p':
			SetParanoiaLevel(1); /* Load symbols on oops. */
			break;

		case 's': /* Use syscall interface. */
			use_syscall = 1;
			break;

		case 'v':
			printf("klogd v%s\n", VERSION);
			exit(1);

		case 'x':
			symbol_lookup = 0;
			break;

		case '?':
			usage(0);
			break;

		default:
			usage(1);
			break;
		}
	}

	/* Set console logging level. */
	if (log_level != NULL) {
		if ((strlen(log_level) > 1) ||
		    (strchr("12345678", *log_level) == NULL)) {
			fprintf(stderr, "klogd: Invalid console logging "
			                "level <%s> specified.\n",
			        log_level);
			return 1;
		}
		console_log_level = *log_level - '0';
	}

	/*
	 * The following code allows klogd to auto-background itself.
	 * What happens is that the program forks and the parent quits.
	 * The child closes all its open file descriptors, and issues a
	 * call to setsid to establish itself as an independent session
	 * immune from control signals.
	 *
	 * fork() is only called if it should run in daemon mode, fork is
	 * not disabled with the command line argument and there's no
	 * such process running.
	 */
	if ((!one_shot) && (!no_fork)) {
		signal(SIGTERM, doexit);
		if (fork() == 0) {
			int num_fds = getdtablesize();
			int fl;

			signal(SIGTERM, SIG_DFL);

			/* This is the child closing its file descriptors. */
			for (fl = 0; fl <= num_fds; ++fl) {
				if (fileno(stdout) == fl && use_output)
					if (strcmp(output, "-") == 0)
						continue;
				close(fl);
			}

			chdir("/");
			setsid();
		} else {
			/*
			 * Parent process
			 */
			sleep(300);
			/*
			 * Not reached unless something major went wrong.
			 */
			exit(1);
			}
	}

	if (pidfile(PidFile)) {
		Syslog(LOG_ERR, "Failed creating PID file %s: %s",
		       PidFile, strerror(errno));
		Terminate();
	}

	/* Signal setups. */
	for (ch = 1; ch < NSIG; ++ch)
		signal(ch, SIG_IGN);
	signal(SIGINT, stop_daemon);
	signal(SIGKILL, stop_daemon);
	signal(SIGTERM, stop_daemon);
	signal(SIGHUP, stop_daemon);
	signal(SIGTSTP, stop_logging);
	signal(SIGCONT, restart);
	signal(SIGUSR1, reload_daemon);
	signal(SIGUSR2, reload_daemon);

	/* Open outputs. */
	if (use_output) {
		if (strcmp(output, "-") == 0)
			output_file = stdout;
		else if ((output_file = fopen(output, "w")) == NULL) {
			fprintf(stderr, "klogd: Cannot open output file "
			                "%s - %s\n",
			        output, strerror(errno));
			return 1;
		}
	} else
		openlog("kernel", 0, LOG_KERN);

	/* Handle one-shot logging. */
	if (one_shot) {
		if (symbol_lookup) {
			InitKsyms(symfile);
			InitMsyms();
		}
		if ((logsrc = GetKernelLogSrc()) == kernel)
			LogKernelLine();
		else
			LogProcLine();
		Terminate();
	}

#if defined(KLOGD_DELAY)
	sleep(KLOGD_DELAY);
#endif

	/* Determine where kernel logging information is to come from. */
	logsrc = GetKernelLogSrc();
	if (symbol_lookup) {
		InitKsyms(symfile);
		InitMsyms();
	}

	if (getpid() != ppid)
		kill(ppid, SIGTERM);

	while (1) {
		if (change_state)
			ChangeLogging();

		switch (logsrc) {
		case kernel:
			LogKernelLine();
			break;

		case proc:
			LogProcLine();
			break;

		case none:
			pause();
			break;
		}
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
