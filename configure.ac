# Copyright (c) 2018-2023  Joachim Wiberg <troglobit@gmail.com>
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

AC_INIT([sysklogd], [2.5.0], [https://github.com/troglobit/sysklogd/issues],,
	[https://github.com/troglobit/sysklogd])
AC_CONFIG_AUX_DIR(aux)
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
		 syslogd.service])

AC_PROG_CC
AC_PROG_INSTALL
AC_HEADER_STDC

# Check for required packages
PKG_PROG_PKG_CONFIG

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([pidfile strlcpy strlcat utimensat])
AC_CONFIG_LIBOBJ_DIR([lib])

# Check for utmp.h
AC_CHECK_HEADERS([utmp.h])

# Check for fork()
AC_CHECK_FUNCS([fork])

# Check for setsid()
AC_CHECK_FUNCS([setsid])

# Check for other library functions
AC_CHECK_FUNCS([getprogname strtobytes])

# Command line options
AC_ARG_WITH(suspend-time,
        AS_HELP_STRING([--with-suspend-time=SEC], [Retry delay for sending to remote, default: 180]),
	[suspend_time=$withval], [suspend_time='no'])

AC_ARG_WITH(systemd,
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files])],,
     [with_systemd=auto])

AC_ARG_WITH(logger,
     AS_HELP_STRING([--without-logger], [Build without extended logger tool, default: enabled]),
     [logger=$withval], [logger='yes'])

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

# Expand $sbindir and @$sysconfdir early, for systemd unit file
# NOTE: This does *not* take prefix/exec_prefix override at "make
#       install" into account, unfortunately.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)
SYSCONFDIR=`eval echo $sysconfdir`
AC_SUBST(SYSCONFDIR)

# Workaround for as-of-yet unreleased runstatedir support, planned for
# autoconf 2.70, which some major distros have backported.
AS_IF([test -z "$runstatedir"], runstatedir="$localstatedir/run")
AC_SUBST(runstatedir)

AC_OUTPUT

# Expand directories for configuration summary, unexpanded defaults:
# runstatedir => ${localstatedir}/run
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
  logger.........: $with_logger
  suspend time...: $suspend_time sec
  systemd........: $with_systemd

------------- Compiler version --------------
$($CC --version || true)
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
