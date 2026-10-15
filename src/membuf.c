/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2024  Joachim Wiberg <troglobit@gmail.com>
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
 *
 * In-memory log buffer for logread(1).  Captures every message in a
 * size-bounded ring and serves it over a UNIX domain control socket,
 * BusyBox/OpenWRT style.  See syslog.conf(5) `membuf'.
 */

#include "config.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "compat.h"
#include "queue.h"
#include "socket.h"
#include "membuf.h"
#include "syslogd.h"

/* One captured log line, newline-terminated and ready to write(2). */
struct mb_line {
	TAILQ_ENTRY(mb_line) link;
	size_t len;		/* bytes in data[], including the newline */
	char   data[];
};

/* A connected logread(1) client. */
struct mb_client {
	LIST_ENTRY(mb_client) link;
	int sd;
	int follow;		/* keep streaming new lines after the dump */
	int dead;		/* write failed; reaped by its read callback */
};

/* Bound concurrent clients so a local user cannot exhaust fds (select()
   has a hard FD_SETSIZE limit) or amplify the per-message fan-out. */
#define MEMBUF_MAX_CLIENTS 24

static TAILQ_HEAD(, mb_line)  mb_lines   = TAILQ_HEAD_INITIALIZER(mb_lines);
static LIST_HEAD(, mb_client) mb_clients = LIST_HEAD_INITIALIZER(mb_clients);

static size_t mb_max;		/* configured byte budget, 0 = disabled  */
static size_t mb_cur;		/* bytes currently held                   */
static int    mb_nclients;	/* number of connected clients           */

static int  mb_sd = -1;		/* listening control socket               */
static char mb_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = _PATH_MEMBUF;
static char mb_bound[sizeof(mb_path)];	/* path mb_sd is currently bound to */
static char mb_owner[64];	/* "user:group" from config, "" = default */


static int mb_is_number(const char *s)
{
	if (!*s)
		return 0;
	for (; *s; s++)
		if (*s < '0' || *s > '9')
			return 0;
	return 1;
}

/*
 * Best-effort full write to a client.  MSG_NOSIGNAL keeps a vanished
 * reader from killing the daemon with SIGPIPE.  The socket is
 * non-blocking, so a reader that cannot keep up (EAGAIN) is treated as
 * gone rather than stalling the daemon -- the caller drops it.
 */
static int mb_write(int sd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = send(sd, buf, len, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}

	return 0;
}

static void mb_client_close(struct mb_client *c)
{
	LIST_REMOVE(c, link);
	socket_close(c->sd);
	free(c);
	mb_nclients--;
}

/* Drop oldest lines until within budget, always keeping the newest. */
static void mb_evict(void)
{
	while (mb_cur > mb_max && TAILQ_NEXT(TAILQ_FIRST(&mb_lines), link)) {
		struct mb_line *old = TAILQ_FIRST(&mb_lines);

		TAILQ_REMOVE(&mb_lines, old, link);
		mb_cur -= old->len;
		free(old);
	}
}

/*
 * Resolve socket owner and access mode.  On a minimal system, or when an
 * explicitly configured user/group cannot be resolved, narrow access to
 * the owner (root) -- never widen it.  Connecting to a UNIX socket needs
 * write permission, hence 0660/0600 rather than 0640/0600.
 */
static void mb_resolve_owner(uid_t *uidp, gid_t *gidp, mode_t *modep)
{
	uid_t uid = 0;		/* default owner: the daemon uid (root) */
	gid_t gid = 0;
	int group_ok = 0;

	if (mb_owner[0]) {
		char spec[sizeof(mb_owner)];
		char *u, *g;
		int ok = 1;

		strlcpy(spec, mb_owner, sizeof(spec));
		u = spec;
		g = strchr(spec, ':');
		if (g)
			*g++ = '\0';

		if (*u) {
			struct passwd *pw = getpwnam(u);

			if (pw)
				uid = pw->pw_uid;
			else if (mb_is_number(u))
				uid = (uid_t)atol(u);
			else
				ok = 0;
		}

		if (g && *g) {
			struct group *gr = getgrnam(g);

			if (gr) {
				gid = gr->gr_gid;
				group_ok = 1;
			} else if (mb_is_number(g)) {
				gid = (gid_t)atol(g);
				group_ok = 1;
			} else
				ok = 0;
		}

		if (!ok) {
			WARN("membuf: cannot resolve owner '%s', restricting "
			     "%s to root only", mb_owner, mb_path);
			uid = 0;
			gid = 0;
			group_ok = 0;
		}
	} else {
		struct group *gr = getgrnam("adm");

		if (gr) {
			gid = gr->gr_gid;
			group_ok = 1;
		}
	}

	if (!group_ok)
		gid = 0;

	*uidp  = uid;
	*gidp  = gid;
	*modep = group_ok ? 0660 : 0600;
}

static int mb_listen(void)
{
	struct sockaddr_un sun = { 0 };
	int sd;

	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, mb_path, sizeof(sun.sun_path));

	(void)unlink(mb_path);

	sd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sd < 0)
		return -1;

	/*
	 * Restrict to owner before listen(), so the socket is never
	 * reachable by others while membuf_init() sets the final owner.
	 */
	if (bind(sd, (struct sockaddr *)&sun, sizeof(sun)) < 0 ||
	    chmod(mb_path, 0600) < 0 ||
	    listen(sd, 8) < 0) {
		close(sd);
		return -1;
	}

	return sd;
}

static void mb_read_cb(int sd, void *arg)
{
	struct mb_client *c = arg;
	struct mb_line *ml;
	char cmd[64];
	ssize_t n;

	n = recv(sd, cmd, sizeof(cmd) - 1, 0);
	if (n <= 0) {
		mb_client_close(c);
		return;
	}
	cmd[n] = '\0';

	/* Stream the current backlog, oldest first. */
	TAILQ_FOREACH(ml, &mb_lines, link) {
		if (mb_write(sd, ml->data, ml->len) < 0) {
			mb_client_close(c);
			return;
		}
	}

	/* "follow" keeps the connection for live lines, "dump" ends here. */
	if (!strncmp(cmd, "follow", 6))
		c->follow = 1;
	else
		mb_client_close(c);
}

static void mb_accept_cb(int sd, void *arg)
{
	struct mb_client *c;
	int cd;

	(void)arg;
	cd = accept4(sd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (cd < 0)
		return;

	if (mb_nclients >= MEMBUF_MAX_CLIENTS) {
		close(cd);
		return;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		close(cd);
		return;
	}
	c->sd = cd;

	if (socket_register(cd, NULL, mb_read_cb, c) < 0) {
		close(cd);
		free(c);
		return;
	}
	LIST_INSERT_HEAD(&mb_clients, c, link);
	mb_nclients++;
}

/*
 * Reset configurable state before re-reading syslog.conf so that a
 * removed `membuf' directive actually disables the buffer on reload.
 */
void membuf_reset(void)
{
	mb_max = 0;
	mb_owner[0] = '\0';
	strlcpy(mb_path, _PATH_MEMBUF, sizeof(mb_path));
}

/* syslog.conf: membuf PATH SIZE [USER:GROUP] */
void membuf_config(char *arg, void *arg2)
{
	char *path, *size, *owner, *sp = NULL;
	int val;

	(void)arg2;

	path = strtok_r(arg, " \t", &sp);
	size = strtok_r(NULL, " \t", &sp);
	if (!path || !size) {
		ERRX("membuf: usage: membuf PATH SIZE [USER:GROUP]");
		return;
	}

	val = strtobytes(size);
	if (val <= 0) {
		ERRX("membuf: invalid buffer size '%s'", size);
		return;
	}

	strlcpy(mb_path, path, sizeof(mb_path));
	mb_max = (size_t)val;

	/* Each directive is self-contained; don't inherit a prior owner. */
	mb_owner[0] = '\0';
	owner = strtok_r(NULL, " \t", &sp);
	if (owner)
		strlcpy(mb_owner, owner, sizeof(mb_owner));
}

int membuf_enabled(void)
{
	return mb_max != 0;
}

void membuf_add(const char *line, size_t len)
{
	struct mb_client *c;
	struct mb_line *ml;

	if (!mb_max || !len)
		return;

	ml = malloc(sizeof(*ml) + len + 1);
	if (!ml)
		return;
	memcpy(ml->data, line, len);
	ml->data[len] = '\n';
	ml->len = len + 1;

	TAILQ_INSERT_TAIL(&mb_lines, ml, link);
	mb_cur += ml->len;
	mb_evict();		/* the new line is the tail, never evicted */

	/*
	 * This runs inside the select loop's socket iteration (a received
	 * message is logged synchronously), so do NOT close a client here --
	 * that frees a node the iteration may still hold.  On write failure,
	 * shut the client down and let its own read callback reap it.
	 */
	LIST_FOREACH(c, &mb_clients, link) {
		if (c->follow && !c->dead &&
		    mb_write(c->sd, ml->data, ml->len) < 0) {
			c->dead = 1;
			shutdown(c->sd, SHUT_RDWR);
		}
	}
}

void membuf_init(void)
{
	uid_t uid;
	gid_t gid;
	mode_t mode;

	if (!mb_max) {
		/* Disabled, or removed on reload -- tear everything down. */
		membuf_exit();
		return;
	}

	mb_evict();		/* a smaller budget may apply after reload */

	/* Re-bind if the configured path changed across a reload. */
	if (mb_sd >= 0 && strcmp(mb_bound, mb_path)) {
		socket_close(mb_sd);
		(void)unlink(mb_bound);
		mb_sd = -1;
	}

	if (mb_sd < 0) {
		mb_sd = mb_listen();
		if (mb_sd < 0) {
			ERR("membuf: cannot create control socket %s, disabling", mb_path);
			goto disable;
		}
		strlcpy(mb_bound, mb_path, sizeof(mb_bound));

		if (socket_register(mb_sd, NULL, mb_accept_cb, NULL) < 0) {
			close(mb_sd);
			(void)unlink(mb_bound);
			mb_sd = -1;
			goto disable;
		}
	}

	/*
	 * The socket is already mode 0600 from mb_listen(); set the owner,
	 * then widen.  If that fails, tear it down rather than serve the
	 * buffer at unverified permissions.
	 */
	mb_resolve_owner(&uid, &gid, &mode);
	if (chown(mb_bound, uid, gid) || chmod(mb_bound, mode)) {
		ERR("membuf: cannot secure control socket %s, disabling", mb_bound);
		goto disable;
	}

	return;
disable:
	/* No reachable, secured socket -- don't buffer logs no one can read. */
	mb_max = 0;
	membuf_exit();
}

void membuf_exit(void)
{
	struct mb_client *c;
	struct mb_line *ml;

	while ((c = LIST_FIRST(&mb_clients)))
		mb_client_close(c);

	while ((ml = TAILQ_FIRST(&mb_lines))) {
		TAILQ_REMOVE(&mb_lines, ml, link);
		free(ml);
	}
	mb_cur = 0;

	if (mb_sd >= 0) {
		socket_close(mb_sd);
		(void)unlink(mb_bound);
		mb_sd = -1;
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
