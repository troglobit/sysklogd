/*
 * Symbols and definitions needed by klogd.
 *
 * Thu Nov 16 12:45:06 CST 1995:  Dr. Wettstein
 *	Initial version.
 */

/* Useful include files. */
#include <stdio.h>
#include <syslog.h>
#include <string.h>


/* Function prototypes. */
extern int InitKsyms(char *);
extern int InitMsyms(void);
extern char * ExpandKadds(char *, char *);
extern void SetParanoiaLevel(int);
extern void Syslog(int priority, char *fmt, ...);
