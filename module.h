/*
    module.h - Miscellaneous module definitions
    Copyright (c) 1996 Richard Henderson <rth@tamu.edu>
    Copyright (c) 2004 Martin Schulze <joey@infodrom.org>

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
 */

#include <asm/atomic.h>

#define MODULE_NAME_LEN 60

struct kernel_sym
{
	unsigned long value;
	char name[MODULE_NAME_LEN];
};


struct list_head {
	struct list_head *next, *prev;
};


struct module_info
{
	unsigned long addr;
	unsigned long size;
	unsigned long flags;
	long usecount;
};


struct module
{
	unsigned long size_of_struct;	/* == sizeof(module) */
	struct module *next;
	const char *name;
	unsigned long size;

	union
	{
		atomic_t usecount;
		long pad;
	} uc;				/* Needs to keep its size - so says rth */

	unsigned long flags;		/* AUTOCLEAN et al */

	unsigned nsyms;
	unsigned ndeps;

	struct module_symbol *syms;
	struct module_ref *deps;
	struct module_ref *refs;
	int (*init)(void);
	void (*cleanup)(void);
	const struct exception_table_entry *ex_table_start;
	const struct exception_table_entry *ex_table_end;
#ifdef __alpha__
	unsigned long gp;
#endif
	/* Members past this point are extensions to the basic
	   module support and are optional.  Use mod_opt_member()
	   to examine them.  */
	const struct module_persist *persist_start;
	const struct module_persist *persist_end;
	int (*can_unload)(void);
};
