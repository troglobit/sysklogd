/*-
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * pidfile.c - interact with pidfiles
 * Copyright (c) 1995  Martin Schulze <Martin.Schulze@Linux.DE>
 *
 * This file is part of the sysklogd package, a kernel and system log daemon.
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
 * You should have received a copy of the GNU General Public License
 * along with this file; see the file COPYING.  If not, write to the
 * Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* read_pid
 *
 * Reads the specified pidfile and returns the read pid.
 * 0 is returned if either there's no pidfile, it's empty
 * or no pid can be read.
 */
int read_pid(char *pidfile)
{
	FILE *fp;
	int pid;

	fp = fopen(pidfile, "r");
	if (!fp)
		return 0;

	fscanf(fp, "%d", &pid);
	fclose(fp);

	return pid;
}

/* check_pid
 *
 * Reads the pid using read_pid and looks up the pid in the process
 * table (using /proc) to determine if the process already exists. If
 * so 1 is returned, otherwise 0.
 */
int check_pid(char *pidfile)
{
	int pid = read_pid(pidfile);

	/* Amazing ! _I_ am already holding the pid file... */
	if ((!pid) || (pid == getpid()))
		return 0;

	/*
	 * The 'standard' method of doing this is to try and do a 'fake' kill
	 * of the process.  If an ESRCH error is returned the process cannot
	 * be found -- GW
	 */
	/* But... errno is usually changed only on error.. */
	if (kill(pid, 0) && errno == ESRCH)
		return 0;

	return pid;
}

/* write_pid
 *
 * Writes the pid to the specified file. If that fails 0 is
 * returned, otherwise the pid.
 */
int write_pid(char *pidfile)
{
	FILE *fp;
	int   fd;
	int   pid;

	if (((fd = open(pidfile, O_RDWR | O_CREAT | O_TRUNC, 0644)) == -1) || ((fp = fdopen(fd, "r+")) == NULL)) {
		fprintf(stderr, "Can't open or create %s.\n", pidfile);
		return 0;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		fscanf(fp, "%d", &pid);
		fclose(fp);
		printf("Can't lock, lock is held by pid %d.\n", pid);
		return 0;
	}

	pid = getpid();
	if (!fprintf(fp, "%d\n", pid)) {
		printf("Can't write pid , %s.\n", strerror(errno));
		close(fd);
		return 0;
	}
	fflush(fp);

	if (flock(fd, LOCK_UN) == -1) {
		printf("Can't unlock pidfile %s, %s.\n", pidfile, strerror(errno));
		close(fd);
		return 0;
	}
	close(fd);

	return pid;
}

/* touch_pid
 *
 * Touches the specified pidfile f.ex. when receiving a SIGHUP
 * The result from utimensat() is returned
 */
int touch_pid(char *pidfile)
{
	return utimensat(0, pidfile, NULL, 0);
}

/* remove_pid
 *
 * Remove the the specified file. The result from unlink(2)
 * is returned
 */
int remove_pid(char *pidfile)
{
	return unlink(pidfile);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
