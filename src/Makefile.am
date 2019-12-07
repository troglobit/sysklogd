# Copyright (c) 2018-2019  Joachim Nilsson <troglobit@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

bin_PROGRAMS          =
sbin_PROGRAMS         = syslogd
lib_LTLIBRARIES       = libsyslog.la
noinst_LTLIBRARIES    = libcompat.la

if ENABLE_LOGGER
bin_PROGRAMS	     += logger
endif

AM_CFLAGS             = -W -Wall -Wextra
AM_CFLAGS            += -Wno-unused-result -Wno-unused-parameter -fno-strict-aliasing
AM_CPPFLAGS           = -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\"
AM_CPPFLAGS          += -D_BSD_SOURCE -D_DEFAULT_SOURCE

syslogd_SOURCES       = syslogd.c syslogd.h socket.c socket.h syslog.h timer.c timer.h queue.h compat.h
syslogd_CPPFLAGS      = $(AM_CPPFLAGS) -D_XOPEN_SOURCE=600
syslogd_LDADD         = $(LIBS) $(LIBOBJS)

logger_SOURCES        = logger.c syslog.h
logger_CPPFLAGS       = $(AM_CPPFLAGS) -D_XOPEN_SOURCE=600
logger_LDADD          = $(LIBS) $(LIBOBJS)
logger_LDADD         += libsyslog.la

# Convenience library for libsyslog instead of linking with $(LTLIBOBJS),
# which would pull in pidfile() and other (strong) symbols as well.
libcompat_la_SOURCES  = ../lib/strlcpy.c ../lib/strlcat.c

pkgconfigdir          = $(libdir)/pkgconfig
pkgincludedir         = $(includedir)/syslog
pkgconfig_DATA        = libsyslog.pc
pkginclude_HEADERS    = syslog.h
libsyslog_la_SOURCES  = syslog.c syslog.h compat.h
libsyslog_la_CPPFLAGS = $(AM_CPPFLAGS) -D_XOPEN_SOURCE=600
libsyslog_la_LDFLAGS  = $(AM_LDFLAGS) -version-info 0:0:0
libsyslog_la_LIBADD   = libcompat.la
