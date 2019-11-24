# Copyright (c) 2018-2019  Joachim Nilsson <troglobit@gmail.com>
#
# This file is part of the sysklogd package, a kernel and system log daemon.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

bin_PROGRAMS          =
sbin_PROGRAMS         = syslogd
lib_LTLIBRARIES       = libsyslog.la
noinst_LTLIBRARIES    = libcompat.la

if ENABLE_KLOGD
sbin_PROGRAMS        += klogd
endif

if ENABLE_LOGGER
bin_PROGRAMS	     += logger
endif

AM_CFLAGS             = -W -Wall -Wextra
AM_CFLAGS            += -Wno-unused-result -Wno-unused-parameter -fno-strict-aliasing
AM_CPPFLAGS           = -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\"
AM_CPPFLAGS          += -D_BSD_SOURCE -D_DEFAULT_SOURCE

syslogd_SOURCES       = syslogd.c syslogd.h socket.c socket.h syslog.h queue.h compat.h
syslogd_CPPFLAGS      = $(AM_CPPFLAGS) -D_XOPEN_SOURCE=600
syslogd_LDADD         = $(LIBS) $(LIBOBJS)

klogd_SOURCES         = klogd.c klogd.h syslog.h compat.h ksym.c ksyms.h ksym_mod.c module.h
klogd_CPPFLAGS        = $(AM_CPPFLAGS)
klogd_LDADD           = $(LIBS) $(LIBOBJS)
klogd_LDADD          += libsyslog.la

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
