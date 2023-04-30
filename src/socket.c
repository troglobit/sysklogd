/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2017-2023  Joachim Wiberg <troglobit@gmail.com>
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
#include <sys/stat.h>

#include "queue.h"
#include "socket.h"
#include "syslogd.h"

struct sock {
	LIST_ENTRY(sock) link;

	struct addrinfo ai;
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
int socket_register(int sd, struct addrinfo *ai, void (*cb)(int, void *), void *arg)
{
	struct sock *entry = NULL;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		goto err;

	if (ai) {
		memcpy(&entry->ai, ai, sizeof(*ai));

		entry->ai.ai_addr = calloc(1, ai->ai_addrlen);
		if (!entry->ai.ai_addr)
			goto eaddr;

		memcpy(entry->ai.ai_addr, ai->ai_addr, ai->ai_addrlen);
	}

	entry->sd  = sd;
	entry->cb  = cb;
	entry->arg = arg;
	LIST_INSERT_HEAD(&sl, entry, link);

	/* Keep track for select() */
	if (sd > max_fdnum)
		max_fdnum = sd;

	return sd;
eaddr:	free(entry);
err:	return -1;
}

static int socket_opts(int sd, int family, int secure)
{
	socklen_t len, slen;
	int on = 1;

	if (secure)
		goto skip;

	/*
	 * This first one is best-effort only, try to increase receive
	 * buffer size.  Alert user on failure and proceed.
	 */
	slen = sizeof(len);
	if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &len, &slen) == 0 && len < RCVBUF_MINSIZE) {
		len = RCVBUF_MINSIZE;
		if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len)))
			ERR("Failed increasing size of socket receive buffer");
	}

skip:	switch (family) {
	case AF_INET6:
		if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
			ERR("setsockopt (IPV6_ONLY), suspending IPv6");
			return -1;
		}
		/* fallthrough */
	case AF_INET:
		if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			ERR("setsockopt(REUSEADDR), suspending inet");
			return -1;
		}
#ifdef SO_REUSEPORT
		if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
			ERR("setsockopt(REUSEPORT), suspending inet");
		}
#endif
		break;
	}

	return 0;
}

/*
 * create socket, with optional callback for reading inbound data
 */
int socket_create(struct addrinfo *ai, void (*cb)(int, void *), void *arg)
{
	struct sockaddr_un *sun = (struct sockaddr_un *)ai->ai_addr;
	mode_t mode = ai->ai_protocol;
	int secure = ai->ai_flags & AI_SECURE;
	int type = ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK;
	int sd;

	if (ai->ai_family == AF_UNIX) {
		(void)unlink(sun->sun_path);
		ai->ai_protocol = 0;
	}

	sd = socket(ai->ai_family, type, ai->ai_protocol);
	if (sd < 0)
		return -1;

	if (socket_opts(sd, ai->ai_family, secure))
		goto err;

	if (secure)
		goto skip;

	if (bind(sd, ai->ai_addr, ai->ai_addrlen) < 0)
		goto err;

skip:	if (ai->ai_family == AF_UNIX) {
		if (chmod(sun->sun_path, mode) < 0)
			goto err;
	}

	if (socket_register(sd, ai, cb, arg) < 0)
		goto err;

	return sd;
err:	close(sd);
	return -1;
}

int socket_close(int sd)
{
	struct sockaddr_un *sun;
	struct sock *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &sl, link, tmp) {
		if (entry->sd != sd)
			continue;

		LIST_REMOVE(entry, link);
		close(entry->sd);
		if (entry->ai.ai_family == AF_UNIX) {
			sun = (struct sockaddr_un *)entry->ai.ai_addr;
			(void)unlink(sun->sun_path);
		}
		free(entry->ai.ai_addr);
		free(entry);

		return 0;
	}

	errno = ENOENT;
	return -1;
}

int socket_ffs(int family)
{
	struct sock *entry;

	LIST_FOREACH(entry, &sl, link) {
		if (entry->ai.ai_family == family)
			return entry->sd;
	}

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
