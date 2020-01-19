/*
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

#ifndef SYSKLOGD_COMPAT_H_
#define SYSKLOGD_COMPAT_H_

#include <config.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/*
 * The following macro is used to remove const cast-away warnings
 * from gcc -Wcast-qual; it should be used with caution because it
 * can hide valid errors; in particular most valid uses are in
 * situations where the API requires it, not to cast away string
 * constants. We don't use *intptr_t on purpose here and we are
 * explicit about unsigned long so that we don't have additional
 * dependencies.
 */
#define __UNCONST(a)	((void *)(unsigned long)(const void *)(a))

/* Pthread wrapper for BSD LWP mutexes */
typedef pthread_mutex_t    mutex_t;

#ifndef mutex_lock
#define MUTEX_INITIALIZER  PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(m)      pthread_mutex_lock(m)
#define mutex_unlock(m)    pthread_mutex_unlock(m)
#endif

/* BSD have sa_len, Linux/GNU doesn't, added with 4.3-Reno */
#if defined(_AIX) || (defined(BSD) && (BSD >= 199006))
#define HAVE_SA_LEN
#endif

#ifndef HAVE_STRLCPY
#define strlcpy __strlcpy
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
#define strlcat __strlcat
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_PIDFILE
#define pidfile __pidfile
int pidfile(const char *basename);
#endif

#ifndef HAVE_UTIMENSAT
#define utimensat __utimensat
int utimensat(int dirfd, const char *pathname, const struct timespec ts[2], int flags);
#endif

#ifndef HAVE_GETPROGNAME
static inline char *getprogname(void)
{
	extern char *__progname;
	return __progname;
}
#endif

#ifndef HAVE_STRTOBYTES
static inline int strtobytes(char *arg)
{
	int mod = 0, bytes;
	size_t pos;

	if (!arg)
		return -1;

	pos = strspn(arg, "0123456789");
	if (arg[pos] != 0) {
		if (arg[pos] == 'G')
			mod = 3;
		else if (arg[pos] == 'M')
			mod = 2;
		else if (arg[pos] == 'k')
			mod = 1;
		else
			return -1;

		arg[pos] = 0;
	}

	bytes = atoi(arg);
	while (mod--)
		bytes *= 1000;

	return bytes;
}
#endif

static inline void parse_rotation(char *optarg, off_t *size, int *num)
{
	char buf[100];
	char *c;
	int sz = 0, cnt = 0;

	strlcpy(buf, optarg, sizeof(buf));
	c = strchr(buf, ':');
	if (c) {
		*c++ = 0;
		cnt  = atoi(c);
	}

	sz = strtobytes(buf);
	if (sz > 0)
		*size = sz;
	if (cnt > 0)
		*num = cnt;
}

#endif /* SYSKLOGD_COMPAT_H_ */
