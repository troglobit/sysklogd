/*-
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * klogd.h - main header file for Linux kernel log daemon.
 *
 * Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef SYSKLOGD_KLOGD_H_
#define SYSKLOGD_KLOGD_H_

#include <stdio.h>
#include <string.h>
#include "syslog.h"

extern int   InitKsyms(char *);
extern int   InitMsyms(void);
extern char *ExpandKadds(char *, char *);
extern void  SetParanoiaLevel(int);
extern void  Syslog(int priority, char *fmt, ...);

#endif /* SYSKLOGD_KLOGD_H_ */
