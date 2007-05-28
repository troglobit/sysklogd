/*
    module.h - Miscellaneous module definitions
    Copyright (c) 1996 Richard Henderson <rth@tamu.edu>
    Copyright (c) 2004-7 Martin Schulze <joey@infodrom.org>

    This file is part of the sysklogd package.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* ChangeLog:
 *
 * Wed Mar 31 17:35:01 CEST 2004: Martin Schulze <joey@infodrom.org>
 *	Created local copy of module.h based on the content of Linux
 *	2.2 since <linux/module.h> doesn't work anymore with its
 *	recent content from Linux 2.4/2.6.
 *
 * Thu May 25 09:14:33 CEST 2006: Martin Schulze <joey@infodrom.org>
 *	Removed asm/atomic.h since it is not needed anymore.
 *
 * Mon May 28 16:46:59 CEST 2007: Martin Schulze <joey@infodrom.org>
 *	Removed several structs not used anymore.  Moved structs from
 *	ksym_mod.c over here.
 */

struct sym_table
{
	unsigned long value;
	char *name;
};

struct Module
{
	struct sym_table *sym_array;
	int num_syms;

	char *name;
};

