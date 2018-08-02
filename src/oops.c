/*
    oops.c - Dummy loadable module for testing klogd.
    Copyright (c) 2007  Martin Schulze <joey@infodrom.org>

    This file is part of the sysklogd package, a kernel and system log daemon.

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

    Helpful documentation: http://www.tldp.org/LDP/lkmpg/2.6/html/

    SYNOPSIS

    echo TEXT > /proc/oops          Emits TEXT via printk at log level
                                    [<address+delta>] triggers klogd address decoding
    echo level: info > /proc/oops   Sets the log level to 'info'
    echo oops > /proc/oops          Creates a real oops, kills executing shell
    cat /proc/oops                  Display current log level and last oops time
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/time.h>

#define MODNAME 	"oops"
#define PROCNAME	"oops"

MODULE_AUTHOR("Martin Schulze <joey@infodrom.org>");
MODULE_DESCRIPTION("Oops module from klogd");
MODULE_LICENSE("GPL");

static DEFINE_MUTEX(oops_lock);

struct oops_t {
  unsigned long lastoops;
  int loglevel;
};
static struct oops_t oops_data;

static int procflag = 0;

struct code {
	char	*name;
	int	level;
};

struct code priorities[] = {
	{"emerg",	0},
	{"panic",	0},		/* DEPRECATED */
	{"alert",	1},
	{"crit",	2},
	{"err",		3},
	{"error",	3},		/* DEPRECATED */
	{"warning",	4},
	{"warn",	4},		/* DEPRECATED */
	{"notice",	5},
	{"info",	6},
	{"debug",	7},
	{NULL,		-1}
};

void oops_decode_level (char *line)
{
  char *p;
  struct code *prio;

  if (strncmp(line, "level:", 6))
    return;

  for (p = (char *)(line) + 6;*p == ' ' || *p == '\t';p++);

  for (prio = priorities; prio->name; prio++)
    if (!strcmp(p, prio->name)) {
      oops_data.loglevel = prio->level;
      return;
    }
}

/*
 * This routine will create a real and ugly oops
 */
static void oops(void)
{
	auto unsigned long *p = (unsigned long *) 828282828;
	*p = 5;
	return;
}

static int oops_proc_open (struct inode *inode, struct file *file)
{
#ifdef DEBUG
  printk (KERN_DEBUG "oops_proc_open().\n");
#endif
  return 0;
}

static ssize_t
oops_proc_read (struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
  char s[70];
  int size;

  struct code *prio;
  char *level = NULL;

#ifdef DEBUG
  printk (KERN_DEBUG "oops_proc_read(%d).\n",nbytes);
#endif

  if (procflag) {
    procflag = 0;
    return 0;
  }

  for (prio = priorities;
       prio->name && prio->level != oops_data.loglevel;
       prio++);
  level = prio->name;

  if (oops_data.lastoops == 0)
    size = sprintf (s, "Log level: %s\nLast oops: none\n", level);
  else {
    unsigned long now = get_seconds();
    unsigned long delta = now - oops_data.lastoops;
    size = sprintf (s, "Log level: %s\nLast oops: %lu (%lu second%s ago)\n", 
		    level, oops_data.lastoops,
		    delta, delta == 1 ? "" : "s");
  }

  if (size < nbytes)
    nbytes = size;

  if (copy_to_user(buf, s, nbytes))
    return -EFAULT;

  *ppos += nbytes;

  procflag++;

  return nbytes;
}

static int
oops_proc_release(struct inode *inode, struct file *filp)
{
#ifdef DEBUG
  printk (KERN_DEBUG "oops_proc_release().\n");
#endif
  return 0;
}

static ssize_t
oops_proc_write(struct file *file, const char __user *buf,
                size_t nbytes, loff_t *ppos)
{
  char input[100];
  int len;

#ifdef DEBUG
  printk (KERN_DEBUG "oops_proc_write(%d).\n", nbytes);
#endif

  len = nbytes >= sizeof(input) ? sizeof(input)-1 : nbytes;

  if (copy_from_user(input, buf, len))
    return -EFAULT;

  input[len] = '\0';
  if (input[len-1] == '\n')
    input[len-1] = '\0';

  if (!strncmp(input, "level:", 6))
    oops_decode_level(input);
  else if (!strcmp(input, "oops")) {
      oops_data.lastoops = get_seconds();
      oops();
  } else
    printk ("<%d>%s\n", oops_data.loglevel, input);

  return nbytes;
}

static const struct file_operations oops_proc_operations = {
  .read = oops_proc_read,
  .release = oops_proc_release,
  .write = oops_proc_write,
  .open = oops_proc_open,
};

void oops_proc_add (void)
{
  struct proc_dir_entry *entry;

  mutex_lock (&oops_lock);

  entry = create_proc_entry (PROCNAME, 0, NULL);

  if (entry) {
    entry->proc_fops = &oops_proc_operations;
  }

  mutex_unlock (&oops_lock);
}

void oops_proc_remove (void)
{
  mutex_lock (&oops_lock);

  remove_proc_entry(PROCNAME, NULL);

  mutex_unlock(&oops_lock);
}

int oops_init (void)
{
  printk (KERN_INFO "Loading module " MODNAME ".\n");

  oops_data.lastoops = 0;
  oops_data.loglevel = 5;

  oops_proc_add();

  return 0;
}

void oops_cleanup (void)
{
  oops_proc_remove();

  printk (KERN_INFO "Removing module " MODNAME ".\n");
}


module_init(oops_init);
module_exit(oops_cleanup);

