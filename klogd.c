/*
    klogd.c - main program for Linux kernel log daemon.
    Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>

    This file is part of the sysklogd package, a kernel and system log daemon.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 * Steve Lord (lord@cray.com) 7th Nov 92
 *
 * Modified to check for kernel info by Dr. G.W. Wettstein 02/17/93.
 *
 * Fri Mar 12 16:53:56 CST 1993:  Dr. Wettstein
 * 	Modified LogLine to use a newline as the line separator in
 *	the kernel message buffer.
 *
 *	Added debugging code to dump the contents of the kernel message
 *	buffer at the start of the LogLine function.
 *
 * Thu Jul 29 11:40:32 CDT 1993:  Dr. Wettstein
 *	Added syscalls to turn off logging of kernel messages to the
 *	console when klogd becomes responsible for kernel messages.
 *
 *	klogd now catches SIGTERM and SIGKILL signals.  Receipt of these
 *	signals cases the clean_up function to be called which shuts down
 *	kernel logging and re-enables logging of messages to the console.
 *
 * Sat Dec 11 11:54:22 CST 1993:  Dr. Wettstein
 *	Added fixes to allow compilation with no complaints with -Wall.
 *
 *      When the daemon catches a fatal signal (SIGTERM, SIGKILL) a 
 *	message is output to the logfile advising that the daemon is
 *	going to terminate.
 *
 * Thu Jan  6 11:54:10 CST 1994:  Dr. Wettstein
 *	Major re-write/re-organization of the code.
 *
 *	Klogd now assigns kernel messages to priority levels when output
 *	to the syslog facility is requested.  The priority level is
 *	determined by decoding the prioritization sequence which is
 *	tagged onto the start of the kernel messages.
 *
 *	Added the following program options: -f arg -c arg -s -o -d
 *
 *		The -f switch can be used to specify that output should
 *		be written to the named file.
 *
 *		The -c switch is used to specify the level of kernel
 *		messages which are to be directed to the console.
 *
 *		The -s switch causes the program to use the syscall
 *		interface to the kernel message facility.  This can be
 *		used to override the presence of the /proc filesystem.
 *
 *		The -o switch causes the program to operate in 'one-shot'
 *		mode.  A single call will be made to read the complete
 *		kernel buffer.  The contents of the buffer will be
 *		output and the program will terminate.
 *
 *		The -d switch causes 'debug' mode to be activated.  This
 *		will cause the daemon to generate LOTS of output to stderr.
 *
 *	The buffer decomposition function (LogLine) was re-written to
 *	squash a bug which was causing only partial kernel messages to
 *	be written to the syslog facility.
 *
 *	The signal handling code was modified to properly differentiate
 *	between the STOP and TSTP signals.
 *
 *	Added pid saving when the daemon detaches into the background.  Thank
 *	you to Juha Virtanen (jiivee@hut.fi) for providing this patch.
 *
 * Mon Feb  6 07:31:29 CST 1995:  Dr. Wettstein
 *	Significant re-organization of the signal handling code.  The
 *	signal handlers now only set variables.  Not earth shaking by any
 *	means but aesthetically pleasing to the code purists in the group.
 *
 *	Patch to make things more compliant with the file system standards.
 *	Thanks to Chris Metcalf for prompting this helpful change.
 *
 *	The routines responsible for reading the kernel log sources now
 *	initialize the buffers before reading.  I think that this will
 *	solve problems with non-terminated kernel messages producing
 *	output of the form:  new old old old
 *
 *	This may also help influence the occassional reports of klogd
 *	failing under significant load.  I think that the jury may still
 *	be out on this one though.  My thanks to Joerg Ahrens for initially
 *	tipping me off to the source of this problem.  Also thanks to
 *	Michael O'Reilly for tipping me off to the best fix for this problem.
 *	And last but not least Mark Lord for prompting me to try this as
 *	a means of attacking the stability problem.
 *
 *	Specifying a - as the arguement to the -f switch will cause output
 *	to be directed to stdout rather than a filename of -.  Thanks to
 *	Randy Appleton for a patch which prompted me to do this.
 *
 * Wed Feb 22 15:37:37 CST 1995:  Dr. Wettstein
 *	Added version information to logging startup messages.
 *
 * Wed Jul 26 18:57:23 MET DST 1995: Martin Schulze
 *	Added an commandline argument "-n" to avoid forking. This obsoletes
 *	the compiler define NO_FORK. It's more useful to have this as an
 *	argument as there are many binary versions and one doesn't need to
 *	recompile the daemon.
 *
 * Thu Aug 10 19:01:08 MET DST 1995: Martin Schulze
 *	Added my pidfile.[ch] to it to perform a better handling with pidfiles.
 *	Now both, syslogd and klogd, can only be started once. They check the
 *	pidfile.
 *
 * Fri Nov 17 15:05:43 CST 1995:  Dr. Wettstein
 *	Added support for kernel address translation.  This required moving
 *	some definitions and includes to the new klogd.h file.  Some small
 *	code cleanups and modifications.
 *
 * Mon Nov 20 10:03:39 MET 1995
 *	Added -v option to print the version and exit.
 *
 * Thu Jan 18 11:19:46 CST 1996:  Dr. Wettstein
 *	Added suggested patches from beta-testers.  These address two
 *	two problems.  The first is segmentation faults which occur with
 *	the ELF libraries.  This was caused by passing a null pointer to
 *	the strcmp function.
 *
 *	Added a second patch to remove the pidfile as part of the
 *	termination cleanup sequence.  This minimizes the potential for
 *	conflicting pidfiles causing immediate termination at boot time.
 *
 * Sun May 12 12:18:21 MET DST 1996:  Martin Schulze
 *	Corrected incorrect/insecure use of strpbrk for a not necessarily
 *	null-terminated buffer.  Used a patch from Chris Hanson
 *	(cph@martigny.ai.mit.edu), thanks.
 */


/* Includes. */
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <linux/time.h>
#include <stdarg.h>
#include <paths.h>
#include "klogd.h"
#include "pidfile.h"
#include "version.h"

#define __LIBRARY__
#include <linux/unistd.h>
#define __NR_sys_syslog __NR_syslog
_syscall3(int,sys_syslog,int, type, char *, buf, int, len);

#define LOG_BUFFER_SIZE 4096
#define LOG_LINE_LENGTH 1024

#if defined(FSSTND)
static char	*PidFile = _PATH_VARRUN "klogd.pid";
#else
static char	*PidFile = "/etc/klogd.pid";
#endif

static int	kmsg,
		change_state = 0,
		terminate = 0,
		caught_TSTP = 0,
		console_log_level = 6;

static int	use_syscall = 0,
		one_shot = 0,
		NoFork = 0;	/* don't fork - don't run in daemon mode */

static char log_buffer[LOG_BUFFER_SIZE];

static FILE *output_file = (FILE *) 0;

static enum LOGSRC {none, proc, kernel} logsrc;

int debugging = 0;


/* Function prototypes. */
extern int sys_syslog(int type, char *buf, int len);
static void CloseLogSrc(void);
extern void restart(int sig);
extern void stop_logging(int sig);
extern void stop_daemon(int sig);
static void Terminate(void);
static void ChangeLogging(void);
static enum LOGSRC GetKernelLogSrc(void);
static void LogLine(char *ptr, int len);
static void LogKernelLine(void);
static void LogProcLine(void);
extern int main(int argc, char *argv[]);


static void CloseLogSrc()

{
	/* Turn on logging of messages to console. */
  	sys_syslog(7, NULL, 0);
  
        /* Shutdown the log sources. */
	switch ( logsrc )
	{
	    case kernel:
		sys_syslog(0, 0, 0);
		Syslog(LOG_INFO, "Kernel logging (sys_syslog) stopped.");
		break;
            case proc:
		close(kmsg);
		Syslog(LOG_INFO, "Kernel logging (proc) stopped.");
		break;
	    case none:
		break;
	}

	if ( output_file != (FILE *) 0 )
		fflush(output_file);
	return;
}


void restart(sig)
	
	int sig;

{
	signal(SIGCONT, restart);
	change_state = 1;
	caught_TSTP = 0;
	return;
}


void stop_logging(sig)

	int sig;
	
{
	signal(SIGTSTP, stop_logging);
	change_state = 1;
	caught_TSTP = 1;
	return;
}


void stop_daemon(sig)

	int sig;

{
	change_state = 1;
	terminate = 1;
	return;
}


static void Terminate()

{
	CloseLogSrc();
	Syslog(LOG_INFO, "Kernel log daemon terminating.");
	sleep(1);
	if ( output_file != (FILE *) 0 )
		fclose(output_file);
	closelog();
	(void) remove_pid(PidFile);
	exit(1);
}

	
static void ChangeLogging(void)

{
	/* Terminate kernel logging. */
	if ( terminate == 1 )
		Terminate();

	/* Stop kernel logging. */
	if ( caught_TSTP == 1 )
	{
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
	if ( logsrc != none )
	{
		Syslog(LOG_INFO, "Kernel logging re-started after SIGSTOP.");
		change_state = 0;
		return;
	}

	/* Restart logging. */
	logsrc = GetKernelLogSrc();
	change_state = 0;
	return;
}


static enum LOGSRC GetKernelLogSrc(void)

{
	auto struct stat sb;


	/* Set level of kernel console messaging.. */
	if ( (sys_syslog(8, NULL, console_log_level) < 0) && \
	     (errno == EINVAL) )
	{
		/*
		 * An invalid arguement error probably indicates that
		 * a pre-0.14 kernel is being run.  At this point we
		 * issue an error message and simply shut-off console
		 * logging completely.
		 */
		Syslog(LOG_WARNING, "Cannot set console log level - disabling "
			      "console output.");
		sys_syslog(6, NULL, 0);
	}
	

	/*
	 * First do a stat to determine whether or not the proc based
	 * file system is available to get kernel messages from.
	 */
	if ( use_syscall ||
	    ((stat(_PATH_KLOG, &sb) < 0) && (errno == ENOENT)) )
	{
	  	/* Initialize kernel logging. */
	  	sys_syslog(1, NULL, 0);
#ifdef DEBRELEASE
		Syslog(LOG_INFO, "klogd %s-%s#%s, log source = sys_syslog "
		       "started.", VERSION, PATCHLEVEL, DEBRELEASE);
#else
		Syslog(LOG_INFO, "klogd %s-%s, log source = sys_syslog "
		       "started.", VERSION, PATCHLEVEL);
#endif
		return(kernel);
	}
	
	if ( (kmsg = open(_PATH_KLOG, O_RDONLY)) < 0 )
	{
		fputs("klogd: Cannot open proc file system.", stderr);
		sys_syslog(7, NULL, 0);
		exit(1);
	}

#ifdef DEBRELEASE
	Syslog(LOG_INFO, "klogd %s-%s#%s, log source = %s started.", \
	       VERSION, PATCHLEVEL, DEBRELEASE, _PATH_KLOG);
#else
	Syslog(LOG_INFO, "klogd %s-%s, log source = %s started.", \
	       VERSION, PATCHLEVEL, _PATH_KLOG);
#endif
	return(proc);
}


extern void Syslog(int priority, char *fmt, ...)

{
	va_list ap;

	if ( debugging )
	{
		fputs("Logging line:\n", stderr);
		fprintf(stderr, "\tLine: %s\n", fmt);
		fprintf(stderr, "\tPriority: %c\n", *(fmt+1));
	}

	/* Handle output to a file. */
	if ( output_file != (FILE *) 0 )
	{
		va_start(ap, fmt);
		vfprintf(output_file, fmt, ap);
		va_end(ap);
		fputc('\n', output_file);
		fflush(output_file);
		fsync(fileno(output_file));
		return;
	}
	
	/* Output using syslog. */
	if ( *fmt == '<' )
	{
		switch ( *(fmt+1) )
		{
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
		fmt += 3;
	}
	
	va_start(ap, fmt);
	vsyslog(priority, fmt, ap);
	va_end(ap);

	return;
}

	
static void LogLine(char *ptr, int len)

{
	auto int idx = 0;
	static int index = 0;
	auto char *nl;
	auto char *pend = ptr + len;
	static char line[LOG_LINE_LENGTH],
		    eline[LOG_LINE_LENGTH];


	if ( debugging && (len != 0) )
	{
		fprintf(stderr, "Log buffer contains: %d characters.\n", len);
		fprintf(stderr, "Line buffer contains: %d characters.\n", \
			index);
		while ( idx <= len )
		{
			fprintf(stderr, "Character #%d - %d:%c\n", idx, \
				ptr[idx], ptr[idx]);
			++idx;
		}
		if ( index != 0 )
		{
			fputs("Line buffer contains an unterminated line:\n", \
			      stderr);
			fprintf(stderr, "\tCount: %d\n", index);
			fprintf(stderr, "%s\n\n", line);
		}
	}

	if ( index == 0 )
		memset(line, '\0', sizeof(line));
	
	while (len) {
		for (nl = ptr; nl < pend; nl += 1)
			if ((*nl == '\n') || (*nl == '\r'))
				break;
		if (nl != pend) {
			len -= nl - ptr + 1;
			strncat(line, ptr, nl - ptr);
			ptr = nl + 1;
			/* Check for empty log line (may be produced if 
			   kernel messages have multiple terminators, eg.
			   \n\r) */
			if ( (*line != '\n') && (*line != '\r') )
			{
				memset(eline, '\0', sizeof(eline));
				ExpandKadds(line, eline);
				Syslog(LOG_INFO, eline);
			}
			index = 0;
			memset(line, '\0', sizeof(line));
		 }
		 else
		 {
			 if ( debugging )
			 {
				 fputs("No terminator - leftover:\n", stderr);
				 fprintf(stderr, "\tCharacters: %d\n", len);
				 fprintf(stderr, "\tIndex: %d\n", index);
				 fputs("\tLine: ", stderr);
				 fprintf(stderr, "%s\n", line);
			 }
			 
			strncat(line, ptr, len);
			index += len;
			len = 0;
		}
	}

	return;
}


static void LogKernelLine(void)

{
	auto int rdcnt;

	/*
	 * Zero-fill the log buffer.  This should cure a multitude of
	 * problems with klogd logging the tail end of the message buffer
	 * which will contain old messages.  Then read the kernel log
	 * messages into this fresh buffer.
	 */
	memset(log_buffer, '\0', sizeof(log_buffer));
	if ( (rdcnt = sys_syslog(2, log_buffer, sizeof(log_buffer))) < 0 )
	{
		if ( errno == EINTR )
			return;
		fprintf(stderr, "Error return from sys_sycall: %d - %s\n", \
			errno, strerror(errno));
	}
	
	LogLine(log_buffer, rdcnt);
	return;
}


static void LogProcLine(void)

{
	auto int rdcnt;

	/*
	 * Zero-fill the log buffer.  This should cure a multitude of
	 * problems with klogd logging the tail end of the message buffer
	 * which will contain old messages.  Then read the kernel messages
	 * from the message pseudo-file into this fresh buffer.
	 */
	memset(log_buffer, '\0', sizeof(log_buffer));
	if ( (rdcnt = read(kmsg, log_buffer, sizeof(log_buffer))) < 0 )
	{
		if ( errno == EINTR )
			return;
		Syslog(LOG_ERR, "Cannot read proc file system.");
	}
	
	LogLine(log_buffer, rdcnt);

	return;
}


int main(argc, argv)

	int argc;

	char *argv[];

{
	auto int ch, use_output = 0;

	auto char	*symfile = (char *) 0,
			*log_level = (char *) 0,
			*output = (char *) 0;

	/* Parse the command-line. */
	while ((ch = getopt(argc, argv, "c:df:k:nosv")) != EOF)
		switch((char)ch)
		{
		    case 'c':		/* Set console message level. */
			log_level = optarg;
			break;
		    case 'd':		/* Activity debug mode. */
			debugging = 1;
			break;
		    case 'f':		/* Define an output file. */
			output = optarg;
			use_output++;
			break;
		    case 'k':		/* Kernel symbol file. */
			symfile = optarg;
			break;
		    case 'n':		/* don't fork */
			NoFork++;
			break;
		    case 'o':		/* One-shot mode. */
			one_shot = 1;
			break;
		    case 's':		/* Use syscall interface. */
			use_syscall = 1;
			break;
		    case 'v':
#ifdef DEBRELEASE
			printf("klogd %s-%s#%s\n", VERSION, PATCHLEVEL, DEBRELEASE);
#else
			printf("klogd %s-%s\n", VERSION, PATCHLEVEL);
#endif			exit (1);
		}


	/* Set console logging level. */
	if ( log_level != (char *) 0 )
	{
		if ( (strlen(log_level) > 1) || \
		     (strchr("1234567", *log_level) == (char *) 0) )
		{
			fprintf(stderr, "klogd: Invalid console logging "
				"level <%s> specified.\n", log_level);
			return(1);
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
	if ( (!one_shot) && (!NoFork) )
	{
		if (!check_pid(PidFile))
		{
			if ( fork() == 0 )
			{
				auto int fl;
				int num_fds = getdtablesize();
		
				/* This is the child closing its file descriptors. */
				for (fl= 0; fl <= num_fds; ++fl)
				{
					if ( fileno(stdout) == fl && use_output )
						if ( strcmp(output, "-") == 0 )
							continue;
					close(fl);
				}
 
				setsid();
			}
			else
				exit(0);
		}
		else
		{
			fputs("klogd: Already running.\n", stderr);
			exit(1);
		}
	}


	/* tuck my process id away */
	if (!check_pid(PidFile))
	{
		if (!write_pid(PidFile))
			Terminate();
	}
	else
	{
		fputs("klogd: Already running.\n", stderr);
		Terminate();
	}
	

	/* Signal setups. */
	for (ch= 1; ch < NSIG; ++ch)
		signal(ch, SIG_IGN);
	signal(SIGINT, stop_daemon);
	signal(SIGKILL, stop_daemon);
	signal(SIGTERM, stop_daemon);
	signal(SIGHUP, stop_daemon);
	signal(SIGTSTP, stop_logging);
	signal(SIGCONT, restart);


	/* Open outputs. */
	if ( use_output )
	{
		if ( strcmp(output, "-") == 0 )
			output_file = stdout;
		else if ( (output_file = fopen(output, "w")) == (FILE *) 0 )
		{
			fprintf(stderr, "klogd: Cannot open output file %s - "\
				"%s\n", output, strerror(errno));
			return(1);
		}
	}
	else
		openlog("kernel", 0, LOG_KERN);


	/* Handle one-shot logging. */
	if ( one_shot )
	{
		InitKsyms(symfile);
		if ( (logsrc = GetKernelLogSrc()) == kernel )
			LogKernelLine();
		else
			LogProcLine();
		Terminate();
	}

	/* Determine where kernel logging information is to come from. */
#if defined(KLOGD_DELAY)
	sleep(KLOGD_DELAY);
#endif
	logsrc = GetKernelLogSrc();
	InitKsyms(symfile);

        /* The main loop. */
	while (1)
	{
		if ( change_state )
			ChangeLogging();
		switch ( logsrc )
		{
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
