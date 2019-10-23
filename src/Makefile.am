#   Copyright (c) 2018  Joachim Nilsson <troglobit@gmail.com>
#
#   This file is part of the sysklogd package, a kernel and system log daemon.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

bin_PROGRAMS     = logger
sbin_PROGRAMS    = syslogd klogd
noinst_PROGRAMS  = tsyslogd syslog_tst

AM_CFLAGS        = -W -Wall -Wextra
AM_CFLAGS       += -Wno-unused-result -Wno-unused-parameter
AM_CFLAGS       += -fomit-frame-pointer -fno-strength-reduce

syslogd_SOURCES  = syslogd.c pidfile.c pidfile.h
syslogd_CPPFLAGS = -DINET6 -D_BSD_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE

klogd_SOURCES    = klogd.c klogd.h syslog.c pidfile.c pidfile.h \
		   ksym.c ksyms.h ksym_mod.c module.h
klogd_CPPFLAGS   = -DALLOW_KERNEL_LOGGING \
		   -D_BSD_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE

logger_SOURCES   = logger.c syslog.c
logger_CPPFLAGS  = -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE

tsyslogd_SOURCES  = syslogd.c pidfile.c pidfile.h
tsyslogd_CPPFLAGS = -DINET6 -D_BSD_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -DTESTING

syslog_tst_SOURCES = syslog_tst.c
