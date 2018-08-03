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

AC_INIT([sysklogd], [1.6-beta1], [https://github.com/troglobit/sysklgd/issues])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/syslogd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])

AC_PROG_CC
AC_PROG_INSTALL
AC_HEADER_STDC

AC_ARG_WITH(klogd-delay,
        AS_HELP_STRING([--with-klogd-delay=SEC], [when started at the same time as syslogd, default: 0]),
	[klogd_delay=$withval], [klogd_delay='no'])

AS_IF([test "x$klogd_delay" != "xno"],[
	AS_IF([test "x$klogd_delay" = "xyes"],[
		AC_MSG_ERROR([Must supply argument])])
	]
	AC_DEFINE_UNQUOTED(KLOGD_DELAY, $klogd_delay, [Delay klogd startup N seconds, default: 0]))

AC_OUTPUT
