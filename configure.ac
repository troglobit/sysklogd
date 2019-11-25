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

AC_INIT([sysklogd], [2.0.1], [https://github.com/troglobit/sysklogd/issues],,
	[https://github.com/troglobit/sysklogd])
AM_INIT_AUTOMAKE([1.11 foreign subdir-objects])
LT_INIT([pic-only])
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/syslogd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile
		 example/Makefile
		 man/Makefile
		 src/Makefile
		 src/libsyslog.pc
		 test/Makefile
		 klogd.service
		 syslogd.service])

AC_PROG_CC
AC_PROG_INSTALL
AC_HEADER_STDC

# Check for required packages
PKG_PROG_PKG_CONFIG

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([pidfile strlcpy strlcat utimensat])
AC_CONFIG_LIBOBJ_DIR([lib])

# Check for other library functions
AC_CHECK_FUNCS([getprogname strtobytes])

# Command line options
AC_ARG_WITH(klogd,
        AS_HELP_STRING([--with-klogd], [Build a separate klogd, default: disabled]),
	[klogd=$withval], [klogd='no'])

AC_ARG_WITH(klogd-delay,
        AS_HELP_STRING([--with-klogd-delay=SEC], [Delay before klogd connects to syslogd, default: 0]),
	[klogd_delay=$withval], [klogd_delay='no'])

AC_ARG_WITH(suspend-time,
        AS_HELP_STRING([--with-suspend-time=SEC], [Retry delay for sending to remote, default: 180]),
	[suspend_time=$withval], [suspend_time='no'])

AC_ARG_WITH(systemd,
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files])],,
     [with_systemd=auto])

AC_ARG_WITH(logger,
     AS_HELP_STRING([--without-logger], [Build without extended logger tool, default: enabled]),
     [logger=$withval], [logger='yes'])

AS_IF([test "x$klogd" != "xno"],
        with_klogd="yes"
	AC_DEFINE(KLOGD, 1, [Build with klogd, default: built-in /dev/kmsg support in syslogd]),
	with_klogd="no")
AM_CONDITIONAL([ENABLE_KLOGD], [test "x$with_klogd" != "xno"])

AS_IF([test "x$klogd_delay" != "xno"],[
	AS_IF([test "x$klogd_delay" = "xyes"],[
		AC_MSG_ERROR([Must supply argument])])
	]
	AC_DEFINE_UNQUOTED(KLOGD_DELAY, $klogd_delay, [Delay klogd startup N seconds, default: 0]),
	klogd_delay=0)

AS_IF([test "x$logger" != "xno"], with_logger="yes", with_logger="no")
AM_CONDITIONAL([ENABLE_LOGGER], [test "x$with_logger" != "xno"])

AS_IF([test "x$suspend_time" != "xno"],[
	AS_IF([test "x$suspend_time" = "xyes"],[
		AC_MSG_ERROR([Must supply argument])])
	]
	AC_DEFINE_UNQUOTED(INET_SUSPEND_TIME, $suspend_time, [Retry delay for sending to remote syslog servers, default: 180]),
	suspend_time=180)

# Check where to install the systemd .service file
AS_IF([test "x$with_systemd" = "xyes" -o "x$with_systemd" = "xauto"], [
     def_systemd=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemd" = "x"],
         [AS_IF([test "x$with_systemd" = "xyes"],
	     [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
	     with_systemd=no], [with_systemd="$def_systemd"])])
AS_IF([test "x$with_systemd" != "xno"],
     [AC_SUBST([systemddir], [$with_systemd])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemd" != "xno"])

# Expand $sbindir early, into $SBINDIR, for systemd unit file
# NOTE: This does *not* take prefix/exec_prefix override at "make
#       install" into account, unfortunately.
test "x$prefix" = xNONE && prefix=
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)

AC_OUTPUT

# Expand directories for configuration summary, unexpanded defaults:
# sysconfdir  => ${prefix}/etc
# runstatedir => ${localstatedir}/run
SYSCONFDIR=`eval echo $sysconfdir`
RUNSTATEDIR=`eval echo $runstatedir`
RUNSTATEDIR=`eval echo $RUNSTATEDIR`

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Sysconfdir.....: $SYSCONFDIR
  Runstatedir....: $RUNSTATEDIR
  C Compiler.....: $CC $CFLAGS $CPPFLAGS $LDFLAGS $LIBS

 Optional features:
  klogd..........: $with_klogd
  klogd delay....: $klogd_delay sec
  logger.........: $with_logger
  suspend time...: $suspend_time sec
  systemd........: $with_systemd

------------- Compiler version --------------
$($CC --version || true)
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
