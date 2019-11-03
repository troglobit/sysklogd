/*-
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ksym.h - Definitions for symbol table utilities.
 *
 * Copyright (c) 1995, 1996  Dr. G.W. Wettstein <greg@wind.rmcc.com>
 * Copyright (c) 1996 Enjellic Systems Development
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

#ifndef SYSKLOGD_KSYMS_H_
#define SYSKLOGD_KSYMS_H_

struct symbol {
	char *name;
	int size;
	int offset;
};

extern char *LookupSymbol(unsigned long, struct symbol *);
extern char *LookupModuleSymbol(unsigned long int, struct symbol *);

#endif /* SYSKLOGD_KSYMS_H_ */
