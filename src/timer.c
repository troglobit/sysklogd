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

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "queue.h"
#include "socket.h"

struct timer {
	LIST_ENTRY(timer) tmr_link;

	int      tmr_period;	/* period time in seconds */
	time_t   tmr_timeout;

	void   (*tmr_cb)(void *arg);
	void    *tmr_arg;
};

static LIST_HEAD(, timer) tmr_head = LIST_HEAD_INITIALIZER();

static struct timespec now;
static int timer_fd[2];

/*
 * what time is it?
 */
int timer_update(void)
{
	return clock_gettime(CLOCK_MONOTONIC, &now);
}

time_t timer_now(void)
{
	return now.tv_sec;
}

/*
 * create periodic timer (seconds)
 */
int timer_add(int period, void (*cb)(void *), void *arg)
{
	struct timer *tmr;

	tmr = calloc(1, sizeof(*tmr));
	if (!tmr)
		return -1;

	tmr->tmr_period = period;
	tmr->tmr_cb     = cb;
	tmr->tmr_arg    = arg;

	LIST_INSERT_HEAD(&tmr_head, tmr, tmr_link);

	return 0;
}

static int __timer_start(void)
{
	struct timer *next, *tmr;
	time_t sec;

	LIST_FOREACH(tmr, &tmr_head, tmr_link) {
		if (tmr->tmr_timeout == 0)
			tmr->tmr_timeout = timer_now() + tmr->tmr_period;
	}

	next = LIST_FIRST(&tmr_head);
	LIST_FOREACH(tmr, &tmr_head, tmr_link) {
		if (next->tmr_timeout > tmr->tmr_timeout)
			next = tmr;
	}

	sec = next->tmr_timeout - timer_now();
	if (sec <= 0)
		sec = 1;

	return alarm((unsigned int)sec);
}

/*
 * start timers
 */
int timer_start(void)
{
	if (LIST_EMPTY(&tmr_head))
		return -1;

	timer_update();

	return __timer_start();
}

/*
 * callback for activity on pipe
 */
static void timer_cb(int sd, void *arg)
{
	struct timer *tmr;
	char dummy;

	(void)read(sd, &dummy, 1);

	timer_update();

	LIST_FOREACH(tmr, &tmr_head, tmr_link) {
		if (tmr->tmr_timeout > timer_now())
			continue;

		if (tmr->tmr_cb)
			tmr->tmr_cb(tmr->tmr_arg);
		tmr->tmr_timeout = 0;
	}

	__timer_start();
}

/*
 * Write to pipe to create an event on SIGALRM
 */
static void sigalarm_handler(int signo)
{
	(void)signo;
	(void)write(timer_fd[1], "!", 1);
}

/*
 * register signal pipe and callback
 */
int timer_init(void)
{
	static int initialized = 0;
	struct sigaction sa;
	int rc;

	if (initialized)
		return 0;

	if (pipe(timer_fd)) {
		warn("pipe()");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigalarm_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL)) {
		warn("sigaction()");
		goto err;
	}

	rc = fcntl(timer_fd[0], F_GETFL, 0);
	if (rc != -1) {
		if (fcntl(timer_fd[0], F_SETFL, rc | O_NONBLOCK) < 0)
			warn("Failed setting pipe() descriptor non-blocking");
	}

	rc = socket_register(timer_fd[0], NULL, timer_cb, NULL);
	if (rc < 0) {
		warn("socket_register()");
		goto err;
	}

	initialized = 1;

	return 0;
err:
	close(timer_fd[0]);
	close(timer_fd[1]);

	return -1;
}

/*
 * deregister signal pipe and callbacks
 */
void timer_exit(void)
{
	struct timer *tmr, *tmp;

	alarm(0);

	socket_close((timer_fd[0]));
	close(timer_fd[1]);

	LIST_FOREACH_SAFE(tmr, &tmr_head, tmr_link, tmp) {
		LIST_REMOVE(tmr, tmr_link);
		free(tmr);
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
