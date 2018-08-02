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

AC_OUTPUT
