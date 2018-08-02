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

sbin_PROGRAMS    = syslogd klogd

AM_CFLAGS        = -fomit-frame-pointer -fno-strength-reduce -Wno-unused-result

syslogd_SOURCES  = syslogd.c pidfile.c pidfile.h
syslogd_CPPFLAGS = -DSYSV -DFSSTND -DSYSLOG_INET -DINET6 -DNO_SCCS	\
		   -DSYSLOG_UNIXAF -DSYSLOGD_PIDNAME=\"syslogd.pid\"

klogd_SOURCES    = klogd.c klogd.h syslog.c pidfile.c pidfile.h 	\
		   ksym.c ksyms.h ksym_mod.c module.h
klogd_CPPFLAGS   = -DSYSV -DFSSTND
