/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2017-2019  Joachim Nilsson <troglobit@gmail.com>
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

#include "config.h"

#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "queue.h"
#include "syslogd.h"

struct sock {
	LIST_ENTRY(sock) link;

	int sd;

	void (*cb)(int, void *arg);
	void *arg;
};

static int max_fdnum = -1;
LIST_HEAD(, sock) sl = LIST_HEAD_INITIALIZER();


int nfds(void)
{
	return max_fdnum + 1;
}

/*
 * register socket/fd/pipe created elsewhere, optional callback
 */
int socket_register(int sd, void (*cb)(int, void *), void *arg)
{
	struct sock *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -1;

	entry->sd  = sd;
	entry->cb  = cb;
	entry->arg = arg;
	LIST_INSERT_HEAD(&sl, entry, link);

#if !defined(HAVE_SOCK_CLOEXEC) && defined(HAVE_FCNTL_H)
	fcntl(sd, F_SETFD, fcntl(sd, F_GETFD) | FD_CLOEXEC);
#endif

	/* Keep track for select() */
	if (sd > max_fdnum)
		max_fdnum = sd;

	return sd;
}

/*
 * create socket, with optional callback for reading inbound data
 */
int socket_create(int domain, int type, int proto, void (*cb)(int, void *), void *arg)
{
	int sd;

#ifdef HAVE_SOCK_CLOEXEC
	type |= SOCK_CLOEXEC;
#endif
	sd = socket(domain, type, proto);
	if (sd < 0)
		return -1;

	if (socket_register(sd, cb, arg) < 0) {
		close(sd);
		return -1;
	}

	return sd;
}

int socket_close(int sd)
{
	struct sock *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &sl, link, tmp) {
		if (entry->sd == sd) {
			LIST_REMOVE(entry, link);
			close(entry->sd);
			free(entry);

			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int socket_poll(struct timeval *timeout)
{
	int num;
	fd_set fds;
	struct sock *entry;

	FD_ZERO(&fds);
	LIST_FOREACH(entry, &sl, link)
		FD_SET(entry->sd, &fds);

	num = select(nfds(), &fds, NULL, NULL, timeout);
	if (num <= 0) {
		/* Log all errors, except when signalled, ignore failures. */
		if (num < 0 && EINTR != errno)
			WARN("Failed select(): %s", strerror(errno));

		return num;
	}

	LIST_FOREACH(entry, &sl, link) {
		if (!FD_ISSET(entry->sd, &fds))
			continue;

		if (entry->cb)
			entry->cb(entry->sd, entry->arg);
	}

	return num;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
