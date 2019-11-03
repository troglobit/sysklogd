/*-
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ksym.c - functions for kernel address->symbol translation
 *
 * Copyright (c) 1995, 1996  Dr. G.W. Wettstein <greg@wind.rmcc.com>
 * Copyright (c) 1996 Enjellic Systems Development
 * Copyright (c) 1997-2007 Martin Schulze <joey@infodrom.org>
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

/*
 * This file contains functions which handle the translation of kernel
 * numeric addresses into symbols for the klogd utility.
 */

#include "klogd.h"
#include "ksyms.h"
#include "module.h"
#include <malloc.h>
#include <stdlib.h>
#include <sys/utsname.h>

#define VERBOSE_DEBUGGING 0

int                      num_syms = 0;
static int               i_am_paranoid = 0;
static char              vstring[12];
static struct sym_table *sym_array = NULL;

static char *system_maps[] =
    {
	    "/boot/System.map",
	    "/System.map",
	    "/usr/src/linux/System.map",
#if defined(TEST)
	    "./System.map",
#endif
	    NULL
    };

#if defined(TEST)
int debugging;
#else
extern int debugging;
#endif

/* Function prototypes. */
static char *FindSymbolFile(void);
static int   AddSymbol(unsigned long, char *);
static void  FreeSymbols(void);
static int   CheckVersion(char *);
static int   CheckMapVersion(char *);

/**************************************************************************
 * Function:	InitKsyms
 *
 * Purpose:	This function is responsible for initializing and loading
 *		the data tables used by the kernel address translations.
 *
 * Arguments:	(char *) mapfile
 *
 *			mapfile:->	A pointer to a complete path
 *					specification of the file containing
 *					the kernel map to use.
 *
 * Return:	int
 *
 *		A boolean style context is returned.  The return value will
 *		be true if initialization was successful.  False if not.
 **************************************************************************/
int InitKsyms(char *mapfile)
{
	unsigned long int address;
	FILE *sym_file;
	char sym[512];
	char type;
	int version = 0;

	/* Check and make sure that we are starting with a clean slate. */
	if (num_syms > 0)
		FreeSymbols();

	/*
	 * Search for and open the file containing the kernel symbols.
	 */
	if (mapfile == NULL) {
		if ((mapfile = FindSymbolFile()) == NULL) {
			Syslog(LOG_WARNING, "Cannot find a map file.");
			if (debugging)
				fputs("Cannot find a map file.\n", stderr);
			return 0;
		}
	}

	if ((sym_file = fopen(mapfile, "r")) == NULL) {
		Syslog(LOG_WARNING, "Cannot open map file: %s.", mapfile);
		if (debugging)
			fprintf(stderr, "Cannot open map file: %s.\n", mapfile);
		return 0;
	}

	/*
	 * Read the kernel symbol table file and add entries for each
	 * line.  I suspect that the use of fscanf is not really in vogue
	 * but it was quick and dirty and IMHO suitable for fixed format
	 * data such as this.  If anybody doesn't agree with this please
	 * e-mail me a diff containing a parser with suitable political
	 * correctness -- GW.
	 */
	while (!feof(sym_file)) {
		if (fscanf(sym_file, "%lx %c %511s\n", &address, &type, sym) != 3) {
			Syslog(LOG_ERR, "Error in symbol table input (#1).");
			fclose(sym_file);
			return 0;
		}
		if (VERBOSE_DEBUGGING && debugging)
			fprintf(stderr, "Address: %lx, Type: %c, Symbol: %s\n",
			        address, type, sym);

		if (AddSymbol(address, sym) == 0) {
			Syslog(LOG_ERR, "Error adding symbol - %s.", sym);
			fclose(sym_file);
			return 0;
		}

		if (version == 0)
			version = CheckVersion(sym);
	}

	Syslog(LOG_INFO, "Loaded %d symbols from %s.", num_syms, mapfile);
	switch (version) {
	case -1:
		Syslog(LOG_WARNING, "Symbols do not match kernel version.");
		num_syms = 0;
		break;

	case 0:
		Syslog(LOG_WARNING, "Cannot verify that symbols match "
		                    "kernel version.");
		break;

	case 1:
		Syslog(LOG_INFO, "Symbols match kernel version %s.", vstring);
		break;
	}

	fclose(sym_file);
	return 1;
}

/**************************************************************************
 * Function:	FindSymbolFile
 *
 * Purpose:	This function is responsible for encapsulating the search
 *		for a valid symbol file.  Encapsulating the search for
 *		the map file in this function allows an intelligent search
 *		process to be implemented.
 *
 *		The list of symbol files will be searched until either a
 *		symbol file is found whose version matches the currently
 *		executing kernel or the end of the list is encountered.  If
 *		the end of the list is encountered the first available
 *		symbol file is returned to the caller.
 *
 *		This strategy allows klogd to locate valid symbol files
 *		for both a production and an experimental kernel.  For
 *		example a map for a production kernel could be installed
 *		in /boot.  If an experimental kernel is loaded the map
 *		in /boot will be skipped and the map in /usr/src/linux would
 *		be used if its version number matches the executing kernel.
 *
 * Arguments:	None specified.
 *
 * Return:	char *
 *
 *		If a valid system map cannot be located a null pointer
 *		is returned to the caller.
 *
 *		If the search is succesful a pointer is returned to the
 *		caller which points to the name of the file containing
 *		the symbol table to be used.
 **************************************************************************/
static char *FindSymbolFile(void)
{
	static char symfile[100];
	struct utsname utsname;
	FILE *sym_file = NULL;
	char **mf = system_maps;
	char *file = NULL;

	if (uname(&utsname) < 0) {
		Syslog(LOG_ERR, "Cannot get kernel version information.");
		return 0;
	}

	if (debugging)
		fputs("Searching for symbol map.\n", stderr);

	for (mf = system_maps; *mf != NULL && file == NULL; ++mf) {

		sprintf(symfile, "%s-%s", *mf, utsname.release);
		if (debugging)
			fprintf(stderr, "Trying %s.\n", symfile);
		if ((sym_file = fopen(symfile, "r")) != NULL) {
			if (CheckMapVersion(symfile) == 1)
				file = symfile;
			fclose(sym_file);
		}
		if (sym_file == NULL || file == NULL) {
			sprintf(symfile, "%s", *mf);
			if (debugging)
				fprintf(stderr, "Trying %s.\n", symfile);
			if ((sym_file = fopen(symfile, "r")) != NULL) {
				if (CheckMapVersion(symfile) == 1)
					file = symfile;
				fclose(sym_file);
			}
		}
	}

	/*
	 * At this stage of the game we are at the end of the symbol
	 * tables.
	 */
	if (debugging)
		fprintf(stderr, "End of search list encountered.\n");
	return file;
}

/**************************************************************************
 * Function:	CheckVersion
 *
 * Purpose:	This function is responsible for determining whether or
 *		the system map being loaded matches the version of the
 *		currently running kernel.
 *
 *		The kernel version is checked by examing a variable which
 *		is of the form:	_Version_66347 (a.out) or Version_66437 (ELF).
 *
 *		The suffix of this variable is the current kernel version
 *		of the kernel encoded in base 256.  For example the
 *		above variable would be decoded as:
 *
 *			(66347 = 1*65536 + 3*256 + 43 = 1.3.43)
 *
 *		(Insert appropriate deities here) help us if Linus ever
 *		needs more than 255 patch levels to get a kernel out the
 *		door... :-)
 *
 * Arguments:	(char *) version
 *
 *			version:->	A pointer to the string which
 *					is to be decoded as a kernel
 *					version variable.
 *
 * Return:	int
 *
 *		       -1:->	The currently running kernel version does
 *				not match this version string.
 *
 *			0:->	The string is not a kernel version variable.
 *
 *			1:->	The executing kernel is of the same version
 *				as the version string.
 **************************************************************************/
static int CheckVersion(char *version)
{
	static char *prefix = { "Version_" };
	int vnum;
	int major;
	int minor;
	int patch;
	struct utsname utsname;
	int kvnum;

	/* Early return if there is no hope. */
	if (strncmp(version, prefix, strlen(prefix)) == 0 /* ELF */ ||
	    (*version == '_' &&
	     strncmp(++version, prefix, strlen(prefix)) == 0) /* a.out */)
		;
	else
		return 0;

	/*
	 * Since the symbol looks like a kernel version we can start
	 * things out by decoding the version string into its component
	 * parts.
	 */
	vnum = atoi(version + strlen(prefix));
	patch = vnum & 0x000000FF;
	minor = (vnum >> 8) & 0x000000FF;
	major = (vnum >> 16) & 0x000000FF;
	if (debugging)
		fprintf(stderr, "Version string = %s, Major = %d, "
		                "Minor = %d, Patch = %d.\n",
		        version +
		            strlen(prefix),
		        major, minor,
		        patch);
	sprintf(vstring, "%d.%d.%d", major, minor, patch);

	/*
	 * We should now have the version string in the vstring variable in
	 * the same format that it is stored in by the kernel.  We now
	 * ask the kernel for its version information and compare the two
	 * values to determine if our system map matches the kernel
	 * version level.
	 */
	if (uname(&utsname) < 0) {
		Syslog(LOG_ERR, "Cannot get kernel version information.");
		return 0;
	}
	if (debugging)
		fprintf(stderr, "Comparing kernel %s with symbol table %s.\n",
		        utsname.release, vstring);

	if (sscanf(utsname.release, "%d.%d.%d", &major, &minor, &patch) < 3) {
		Syslog(LOG_ERR, "Kernel send bogus release string `%s'.",
		       utsname.release);
		return 0;
	}

	/* Compute the version code from data sent by the kernel */
	kvnum = (major << 16) | (minor << 8) | patch;

	/* Failure. */
	if (vnum != kvnum)
		return -1;

	/* Success. */
	return 1;
}

/**************************************************************************
 * Function:	CheckMapVersion
 *
 * Purpose:	This function is responsible for determining whether or
 *		the system map being loaded matches the version of the
 *		currently running kernel.  It uses CheckVersion as
 *		backend.
 *
 * Arguments:	(char *) fname
 *
 *			fname:->	A pointer to the string which
 *					references the system map file to
 *					be used.
 *
 * Return:	int
 *
 *		       -1:->	The currently running kernel version does
 *				not match the version in the given file.
 *
 *			0:->	No system map file or no version information.
 *
 *			1:->	The executing kernel is of the same version
 *				as the version of the map file.
 **************************************************************************/
static int CheckMapVersion(char *fname)
{
	unsigned long int address;
	FILE *sym_file;
	char sym[512];
	char type;
	int version;

	if ((sym_file = fopen(fname, "r")) != NULL) {
		/*
		 * At this point a map file was successfully opened.  We
		 * now need to search this file and look for version
		 * information.
		 */
		Syslog(LOG_INFO, "Inspecting %s", fname);

		version = 0;
		while (!feof(sym_file) && (version == 0)) {
			if (fscanf(sym_file, "%lx %c %511s\n", &address,
			           &type, sym) != 3) {
				Syslog(LOG_ERR, "Error in symbol table input (#2).");
				fclose(sym_file);
				return 0;
			}
			if (VERBOSE_DEBUGGING && debugging)
				fprintf(stderr, "Address: %lx, Type: %c, "
				                "Symbol: %s\n",
				        address, type, sym);

			version = CheckVersion(sym);
		}
		fclose(sym_file);

		switch (version) {
		case -1:
			Syslog(LOG_ERR, "Symbol table has incorrect "
			                "version number.\n");
			break;

		case 0:
			if (debugging)
				fprintf(stderr, "No version information "
				                "found.\n");
			break;
		case 1:
			if (debugging)
				fprintf(stderr, "Found table with "
				                "matching version number.\n");
			break;
		}

		return version;
	}

	return 0;
}

/**************************************************************************
 * Function:	AddSymbol
 *
 * Purpose:	This function is responsible for adding a symbol name
 *		and its address to the symbol table.
 *
 * Arguments:	(unsigned long) address, (char *) symbol
 *
 * Return:	int
 *
 *		A boolean value is assumed.  True if the addition is
 *		successful.  False if not.
 **************************************************************************/
static int AddSymbol(unsigned long address, char *symbol)
{
	/* Allocate the the symbol table entry. */
	sym_array = realloc(sym_array, (num_syms + 1) * sizeof(struct sym_table));
	if (sym_array == NULL)
		return 0;

	/* Then the space for the symbol. */
	sym_array[num_syms].name = malloc(strlen(symbol) * sizeof(char) + 1);
	if (sym_array[num_syms].name == NULL)
		return 0;

	sym_array[num_syms].value = address;
	strcpy(sym_array[num_syms].name, symbol);
	++num_syms;
	return 1;
}

/**************************************************************************
 * Function:	LookupSymbol
 *
 * Purpose:	Find the symbol which is related to the given kernel
 *		address.
 *
 * Arguments:	(long int) value, (struct symbol *) sym
 *
 *		value:->	The address to be located.
 * 
 *		sym:->		A pointer to a structure which will be
 *				loaded with the symbol's parameters.
 *
 * Return:	(char *)
 *
 *		If a match cannot be found a diagnostic string is printed.
 *		If a match is found the pointer to the symbolic name most
 *		closely matching the address is returned.
 **************************************************************************/
char *LookupSymbol(unsigned long value, struct symbol *sym)
{
	struct symbol ksym, msym;
	char *last;
	char *name;
	int lp;

	if (!sym_array)
		return NULL;

	last = sym_array[0].name;
	ksym.offset = 0;
	ksym.size = 0;
	if (value < sym_array[0].value)
		return NULL;

	for (lp = 0; lp <= num_syms; ++lp) {
		if (sym_array[lp].value > value) {
			ksym.offset = value - sym_array[lp - 1].value;
			ksym.size = sym_array[lp].value -
			            sym_array[lp - 1].value;
			break;
		}
		last = sym_array[lp].name;
	}

	name = LookupModuleSymbol(value, &msym);

	if (ksym.offset == 0 && msym.offset == 0) {
		return NULL;
	}

	if (ksym.offset == 0 || msym.offset < 0 ||
	    (ksym.offset > 0 && ksym.offset < msym.offset)) {
		sym->offset = ksym.offset;
		sym->size = ksym.size;
		return last;
	} else {
		sym->offset = msym.offset;
		sym->size = msym.size;
		return name;
	}

	return NULL;
}

/**************************************************************************
 * Function:	FreeSymbols
 *
 * Purpose:	This function is responsible for freeing all memory which
 *		has been allocated to hold the static symbol table.  It
 *		also initializes the symbol count and in general prepares
 *		for a re-read of a static symbol table.
 *
 * Arguments:  void
 *
 * Return:	void
 **************************************************************************/

static void FreeSymbols(void)
{
	int lp;

	/* Free each piece of memory allocated for symbol names. */
	for (lp = 0; lp < num_syms; ++lp)
		free(sym_array[lp].name);

	/* Whack the entire array and initialize everything. */
	free(sym_array);
	sym_array = NULL;
	num_syms = 0;
}

/**************************************************************************
 * Function:	LogExpanded
 *
 * Purpose:	This function is responsible for logging a kernel message
 *		line after all potential numeric kernel addresses have
 *		been resolved symolically.
 *
 * Arguments:	(char *) line, (char *) el
 *
 *		line:->	A pointer to the buffer containing the kernel
 *			message to be expanded and logged.
 *
 *		el:->	A pointer to the buffer into which the expanded
 *			kernel line will be written.
 *
 * Return:	void
 **************************************************************************/

char *ExpandKadds(char *line, char *el)
{
	unsigned long int value;
	struct symbol sym;
	char *symbol;
	char *elp = el;
	char *sl  = line;
	char *kp;
	char num[15];

	sym.offset = 0;
	sym.size = 0;

	/*
	 * This is as handy a place to put this as anyplace.
	 *
	 * Since the insertion of kernel modules can occur in a somewhat
	 * dynamic fashion we need some mechanism to insure that the
	 * kernel symbol tables get read just prior to when they are
	 * needed.
	 *
	 * To accomplish this we look for the Oops string and use its
	 * presence as a signal to load the module symbols.
	 *
	 * This is not the best solution of course, especially if the
	 * kernel is rapidly going out to lunch.  What really needs to
	 * be done is to somehow generate a callback from the
	 * kernel whenever a module is loaded or unloaded.  I am
	 * open for patches.
	 */
	if (i_am_paranoid &&
	    (strstr(line, "Oops:") != NULL) && !InitMsyms())
		Syslog(LOG_WARNING, "Cannot load kernel module symbols.\n");

	/*
	 * Early return if there do not appear to be any kernel
	 * messages in this line.
	 */
	if ((num_syms == 0) ||
	    (kp = strstr(line, "[<")) == NULL) {
		strcpy(el, line);
		return el;
	}

	/* Loop through and expand all kernel messages. */
	do {
		while (sl < kp + 1)
			*elp++ = *sl++;

		/* Now poised at a kernel delimiter. */
		if ((kp = strstr(sl, ">]")) == NULL) {
			strcpy(el, sl);
			return el;
		}

		strncpy(num, sl + 1, kp - sl - 1);
		num[kp - sl - 1] = '\0';
		value = strtoul(num, NULL, 16);
		if ((symbol = LookupSymbol(value, &sym)) == NULL)
			symbol = sl;

		strcat(elp, symbol);
		elp += strlen(symbol);
		if (debugging)
			fprintf(stderr, "Symbol: %s = %lx = %s, %x/%d\n",
			        sl + 1, value,
			        (sym.size == 0) ? symbol + 1 : symbol,
			        sym.offset, sym.size);

		value = 2;
		if (sym.size != 0) {
			--value;
			++kp;
			elp += sprintf(elp, "+0x%x/0x%02x", sym.offset, sym.size);
		}
		strncat(elp, kp, value);
		elp += value;
		sl = kp + value;
		if ((kp = strstr(sl, "[<")) == NULL)
			strcat(elp, sl);
	} while (kp != NULL);

	if (debugging)
		fprintf(stderr, "Expanded line: %s\n", el);
	return el;
}

/**************************************************************************
 * Function:	SetParanoiaLevel
 *
 * Purpose:	This function is an interface function for setting the
 *		mode of loadable module symbol lookups.  Probably overkill
 *		but it does slay another global variable.
 *
 * Arguments:	(int) level
 *
 *		level:->	The amount of paranoia which is to be
 *				present when resolving kernel exceptions.
 * Return:	void
 **************************************************************************/
void SetParanoiaLevel(int level)
{
	i_am_paranoid = level;
}

/*
 * Setting the -DTEST define enables the following code fragment to
 * be compiled.  This produces a small standalone program which will
 * echo the standard input of the process to stdout while translating
 * all numeric kernel addresses into their symbolic equivalent.
 */
#if defined(TEST)

#include <stdarg.h>

int main(int argc, char *argv[])
{
	char line[1024], eline[2048];

	debugging = 1;

	if (!InitKsyms(NULL)) {
		fputs("ksym: Error loading system map.\n", stderr);
		return 1;
	}

	while (!feof(stdin)) {
		fgets(line, sizeof(line), stdin);
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0'; /* Trash NL char */
		memset(eline, 0, sizeof(eline));
		ExpandKadds(line, eline);
		fprintf(stdout, "%s\n", eline);
	}

	return 0;
}

void Syslog(int priority, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stdout, "Pr: %d, ", priority);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
}
#endif

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
