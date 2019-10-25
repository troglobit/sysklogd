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

AC_INIT([sysklogd], [2.0-beta1], [https://github.com/troglobit/sysklogd/issues],,
	[https://github.com/troglobit/sysklogd])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/syslogd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile klogd.service syslogd.service])

AC_PROG_CC
AC_PROG_INSTALL
AC_HEADER_STDC

# Check for required packages
PKG_PROG_PKG_CONFIG

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([strlcpy strlcat])
AC_CONFIG_LIBOBJ_DIR([lib])

# Command line options
AC_ARG_WITH(suspend-time,
        AS_HELP_STRING([--with-suspend-time=SEC], [Retry timeout for remote syslogd servers, default: 180]),
	[suspend_time=$withval], [suspend_time='no'])

AC_ARG_WITH(klogd-delay,
        AS_HELP_STRING([--with-klogd-delay=SEC], [when started at the same time as syslogd, default: 0]),
	[klogd_delay=$withval], [klogd_delay='no'])

AC_ARG_WITH(syslogd-pidfile,
        AS_HELP_STRING([--with-syslogd-pidfile=FILE], [custom PID file, default: syslogd.pid]),
	[syslogd_pidfile=$withval], [syslogd_pidfile='no'])

AC_ARG_WITH(systemd,
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files])],,
     [with_systemd=auto])

AS_IF([test "x$suspend_time" != "xno"],[
	AS_IF([test "x$suspend_time" = "xyes"],[
		AC_MSG_ERROR([Must supply argument])])
	]
	AC_DEFINE_UNQUOTED(INET_SUSPEND_TIME, $suspend_time, [Retry timeout for remote syslgod servers, default: 180]))

AS_IF([test "x$klogd_delay" != "xno"],[
	AS_IF([test "x$klogd_delay" = "xyes"],[
		AC_MSG_ERROR([Must supply argument])])
	]
	AC_DEFINE_UNQUOTED(KLOGD_DELAY, $klogd_delay, [Delay klogd startup N seconds, default: 0]))

AS_IF([test "x$syslogd_pidfile" != "xno"],[
	AS_IF([test "x$syslogd_pidfile" = "xyes"],[
		AC_MSG_ERROR([Must supply argument])])
	]
	AC_DEFINE_UNQUOTED(SYSLOGD_PIDNAME, "$syslogd_pidfile", [Custom syslogd PID file]))

# Check where to install the systemd .service file
AS_IF([test "x$with_systemd" = "xyes" -o "x$with_systemd" = "xauto"], [
     def_systemd=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemd" = "x"],
         [AS_IF([test "x$with_systemd" = "xyes"],
	     [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
	     with_systemd=no], [with_systemd="$def_systemd"])]
)
AS_IF([test "x$with_systemd" != "xno"],
     [AC_SUBST([systemddir], [$with_systemd])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemd" != "xno"])

# Expand $sbindir early, into $SBINDIR, for systemd unit file
# NOTE: This does *not* take prefix/exec_prefix override at "make
#       install" into account, unfortunately.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)

AC_OUTPUT
