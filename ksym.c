/*
    ksym.c - functions for kernel address->symbol translation
    Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>

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
*/

/*
 * This file contains functions which handle the translation of kernel
 * numeric addresses into symbols for the klogd utility.
 *
 * Sat Oct 28 09:00:14 CDT 1995:  Dr. Wettstein
 *	Initial Version.
 *
 * Fri Nov 24 12:50:52 CST 1995:  Dr. Wettstein
 *	Added VERBOSE_DEBUGGING define to make debugging output more
 *	manageable.
 *
 *	Added support for verification of the loaded kernel symbols.  If
 *	no version information can be be found in the mapfile a warning
 *	message is issued but translation will still take place.  This
 *	will be the default case if kernel versions < 1.3.43 are used.
 *
 *	If the symbols in the mapfile are of the same version as the kernel
 *	that is running an informative message is issued.  If the symbols
 *	in the mapfile do not match the current kernel version a warning
 *	message is issued and translation is disabled.
 *
 * Wed Dec  6 16:14:11 CST 1995:  Dr. Wettstein
 *	Added /boot/System.map to the list of symbol maps to search for.
 *	Also made this map the first item in the search list.  I am open
 *	to CONSTRUCTIVE suggestions for any additions or corrections to
 *	the list of symbol maps to search for.  Be forewarned that the
 *	list in use is the consensus agreement between myself, Linus and
 *	some package distributers.  It is a given that no list will suit
 *	everyone's taste.  If you have rabid concerns about the list
 *	please feel free to edit the system_maps array and compile your
 *	own binaries.
 *
 *	Added support for searching of the list of symbol maps.  This
 *	allows support for access to multiple symbol maps.  The theory
 *	behind this is that a production kernel may have a system map in
 *	/boot/System.map.  If a test kernel is booted this system map
 *	would be skipped in favor of one found in /usr/src/linux.
 *
 * Thu Jan 18 11:18:31 CST 1996:  Dr. Wettstein
 *	Added patch from beta-testers to allow for reading of both
 *	ELF and a.out map files.
 *
 */


/* Includes. */
#include <stdlib.h>
#include <malloc.h>
#include <sys/utsname.h>
#include "klogd.h"

#define VERBOSE_DEBUGGING 0


/* Variables, structures and type definitions static to this module. */
struct sym_table
{
	unsigned long value;
	char *name;
};

struct symbol
{
	char *name;
	int size;
	int offset;
};

static struct sym_table *sym_array = (struct sym_table *) 0;

static int num_syms = 0;

static char *system_maps[] =
{
	"/boot/System.map",
	"/System.map",
	"/usr/src/linux/System.map",
#if defined(TEST)
	"./System.map",
#endif
	(char *) 0
};


#if defined(TEST)
static int debugging = 1;
#else
extern int debugging;
#endif


/* Function prototypes. */
static char * FindSymbolFile(void);
static int AddSymbol(unsigned long, char*);
static char * LookupSymbol(unsigned long, struct symbol *);
static int CheckVersion(char *);


/**************************************************************************
 * Function:	InitKsyms
 *
 * Purpose:	This function is responsible for initializing and loading
 *		the data tables used by the kernel address translations.
 *
 * Arguements:	(char *) mapfile
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

extern int InitKsyms(mapfile)

	char *mapfile;

{
	auto char	type,
			sym[512];

	auto int version = 0;

	auto unsigned long int address;

	auto FILE *sym_file;


	/*
	 * Search for and open the file containing the kernel symbols.
	 */
	if ( mapfile != (char *) 0 )
	{
		if ( (sym_file = fopen(mapfile, "r")) == (FILE *) 0 )
		{
			Syslog(LOG_WARNING, "Cannot open map file: %s.", \
			       mapfile);
			return(0);
		}
	}
	else
	{
		if ( (mapfile = FindSymbolFile()) == (char *) 0 ) 
		{
			Syslog(LOG_WARNING, "Cannot find map file.");
			if ( debugging )
				fputs("Cannot find map file.\n", stderr);
			return(0);
		}
		
		if ( (sym_file = fopen(mapfile, "r")) == (FILE *) 0 )
		{
			Syslog(LOG_WARNING, "Cannot open map file.");
			if ( debugging )
				fputs("Cannot open map file.\n", stderr);
			return(0);
		}
	}
	

	/*
	 * Read the kernel symbol table file and add entries for each
	 * line.  I suspect that the use of fscanf is not really in vogue
	 * but it was quick and dirty and IMHO suitable for fixed format
	 * data such as this.  If anybody doesn't agree with this please
	 * e-mail me a diff containing a parser with suitable political
	 * correctness -- GW.
	 */
	while ( !feof(sym_file) )
	{
		if ( fscanf(sym_file, "%8lx %c %s\n", &address, &type, sym)
		    != 3 )
		{
			Syslog(LOG_ERR, "Error in symbol table input.");
			fclose(sym_file);
			return(0);
		}
		if ( VERBOSE_DEBUGGING && debugging )
			fprintf(stderr, "Address: %lx, Type: %c, Symbol: %s\n",
				address, type, sym);

		if ( AddSymbol(address, sym) == 0 )
		{
			Syslog(LOG_ERR, "Error adding symbol - %s.", sym);
			return(0);
		}

		if ( version == 0 )
			version = CheckVersion(sym);
	}
	

	Syslog(LOG_INFO, "Loaded %d symbols from %s.", num_syms, mapfile);
	switch ( version )
	{
	    case -1:
		Syslog(LOG_WARNING, "Symbols do not match kernel version.");
		num_syms = 0;
		break;

	    case 0:
		Syslog(LOG_WARNING, "Cannot verify that symbols match " \
		       "kernel version.");
		break;
		
	    case 1:
		Syslog(LOG_INFO, "Symbols match kernel version.");
		break;
	}
		
	fclose(sym_file);
	return(1);
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
 * Arguements:	None specified.
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

static char * FindSymbolFile()

{
	auto char	type,
			*file = (char *) 0,
			**mf = system_maps,
			sym[512];

	auto int version;
	
	auto unsigned long int address;

	auto FILE *sym_file = (FILE *) 0;


	if ( debugging )
		fputs("Searching for symbol map.\n", stderr);
	
	for (mf = system_maps; *mf != (char *) 0; ++mf)
	{
		if ( debugging )
			fprintf(stderr, "Trying %s.\n", *mf);
		if ( (sym_file = fopen(*mf, "r")) == (FILE *) 0 )
			continue;
		
		/*
		 * At this point a map file was successfully opened.  We
		 * now need to search this file and look for a version
		 * version information.
		 */
		version = 0;
		while ( !feof(sym_file) && (version == 0) )
		{
			if ( fscanf(sym_file, "%8lx %c %s\n", &address, \
				    &type, sym) != 3 )
			{
				Syslog(LOG_ERR, "Error in symbol table input.");
				fclose(sym_file);
				return((char *) 0);
			}
			if ( VERBOSE_DEBUGGING && debugging )
				fprintf(stderr, "Address: %lx, Type: %c, " \
				    "Symbol: %s\n", address, type, sym);

			version = CheckVersion(sym);
		}
		fclose(sym_file);

		switch ( version )
		{
		    case -1:
			if ( debugging )
				fprintf(stderr, "Symbol table has incorrect " \
					"version number.\n");
			break;
			
		    case 0:
			if ( debugging )
				fprintf(stderr, "No version information " \
					"found.\n");
			if ( file == (char *) 0 )
			{
				if ( debugging )
					fputs("Saving filename.\n", stderr);
				file = *mf;
			}
			break;
		    case 1:
			if ( debugging )
				fprintf(stderr, "Found table with " \
					"matching version number.\n");
			return(*mf);
			break;
		}
	}


	/*
	 * At this stage of the game we are at the end of the symbol
	 * tables.  We have evidently not found a symbol map whose version
	 * information matches the currently executing kernel.  If possible
	 * we return a pointer to the first valid symbol map that was
	 * encountered.
	 */
	if ( debugging )
		fprintf(stderr, "End of search list encountered.\n");
	return(file);
}


/**************************************************************************
 * Function:	CheckVersion
 *
 * Purpose:	This function is responsible for determining whether or
 *		the system map being loaded matches the version of the
 *		currently running kernrel.
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
 * Arguements:	(char *) version
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

static int CheckVersion(version)

	char *version;
	

{
	auto char vstring[6];

	auto int	vnum,
			major,
			minor,
			patch;

	auto struct utsname utsname;

	static char *prefix = { "Version_" };


	/* Early return if there is no hope. */
	if ( strncmp(version, prefix, strlen(prefix)) == 0  /* ELF */ ||
	   (*version == '_' &&
		strncmp(++version, prefix, strlen(prefix)) == 0 ) /* a.out */ )
		;
	else
		return(0);


	/*
	 * Since the symbol looks like a kernel version we can start
	 * things out by decoding the version string into its component
	 * parts.
	 */
	memset(vstring, '\0', sizeof(vstring));
	strncpy(vstring, version + strlen(prefix), sizeof(vstring)-1);
	vnum = atoi(vstring);
	major = vnum / 65536;
	vnum -= (major * 65536);
	minor = vnum / 256;
	patch = vnum - (minor * 256);
	if ( debugging )
		fprintf(stderr, "Version string = %s, Major = %d, " \
		       "Minor = %d, Patch = %d.\n", vstring, major, minor, \
		       patch);
	sprintf(vstring, "%d.%d.%d", major, minor, patch);

	/*
	 * We should now have the version string in the vstring variable in
	 * the same format that it is stored in by the kernel.  We now
	 * ask the kernel for its version information and compare the two
	 * values to determine if our system map matches the kernel
	 * version level.
	 */
	if ( uname(&utsname) < 0 )
	{
		Syslog(LOG_ERR, "Cannot get kernel version information.");
		return(0);
	}
	if ( debugging )
		fprintf(stderr, "Comparing kernel %s with symbol table %s.\n",\
		       utsname.release, vstring);

	/* Failure. */
	if ( strcmp(vstring, utsname.release) != 0 )
		return(-1);

	/* Success. */
	return(1);
}

	
/**************************************************************************
 * Function:	AddSymbol
 *
 * Purpose:	This function is responsible for adding a symbol name
 *		and its address to the symbol table.
 *
 * Arguements:	(unsigned long) address, (char *) symbol
 *
 * Return:	int
 *
 *		A boolean value is assumed.  True if the addition is
 *		successful.  False if not.
 **************************************************************************/

static int AddSymbol(address, symbol)

	unsigned long address;
	
	char *symbol;
	
{
	/* Allocate the the symbol table entry. */
	sym_array = (struct sym_table *) realloc(sym_array, (num_syms+1) * \
						 sizeof(struct sym_table));
	if ( sym_array == (struct sym_table *) 0 )
		return(0);

	/* Then the space for the symbol. */
	sym_array[num_syms].name = (char *) malloc(strlen(symbol)*sizeof(char)\
						   + 1);
	if ( sym_array[num_syms].name == (char *) 0 )
		return(0);
	
	sym_array[num_syms].value = address;
	strcpy(sym_array[num_syms].name, symbol);
	++num_syms;
	return(1);
}


/**************************************************************************
 * Function:	LookupSymbol
 *
 * Purpose:	Find the symbol which is related to the given kernel
 *		address.
 *
 * Arguements:	(long int) value, (struct symbol *) sym
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

extern char * LookupSymbol(value, sym)

	unsigned long value;

	struct symbol *sym;
	
{
	auto int lp;
	
	auto char *last = sym_array[0].name;


	sym->offset = 0;
	sym->size = 0;
	if ( value < sym_array[0].value )
		return((char *) 0);
	
	for(lp= 0; lp <= num_syms; ++lp)
	{
		if ( sym_array[lp].value > value )
		{		
			sym->offset = value - sym_array[lp-1].value;
			sym->size = sym_array[lp].value - \
				sym_array[lp-1].value;
			return(last);
		}
		last = sym_array[lp].name;
	}

	return((char *) 0);
}


/**************************************************************************
 * Function:	LogExpanded
 *
 * Purpose:	This function is responsible for logging a kernel message
 *		line after all potential numeric kernel addresses have
 *		been resolved symolically.
 *
 * Arguements:	(char *) line, (char *) el
 *
 *		line:->	A pointer to the buffer containing the kernel
 *			message to be expanded and logged.
 *
 *		el:->	A pointer to the buffer into which the expanded
 *			kernel line will be written.
 *
 * Return:	void
 **************************************************************************/

extern char * ExpandKadds(line, el)

	char *line;

	char *el;
	
{
	auto char	dlm,
			*kp,
			*sl = line,
			*elp = el,
			*symbol;

	auto int value;

	auto struct symbol sym;
	
	
	/*
	 * Early return if there do not appear to be any kernel
	 * messages in this line.
	 */
	if ( (num_syms == 0) ||
	     (kp = strstr(line, "[<")) == (char *) 0 )
	{
		strcpy(el, line);
		return(el);
	}

	/* Loop through and expand all kernel messages. */
	do
	{
		while ( sl < kp+1 )
			*elp++ = *sl++;

		/* Now poised at a kernel delimiter. */
	        if ( (kp = strstr(sl, ">]")) == (char *) 0 )
		{
			strcpy(el, sl);
			return(el);
		}
		dlm = *kp;
		*kp = '\0';
		value = strtol(sl+1, (char **) 0, 16);
		if ( (symbol = LookupSymbol(value, &sym)) == (char *) 0 )
			symbol = sl;
			
		strcat(elp, symbol);
		elp += strlen(symbol);
		if ( debugging )
			fprintf(stderr, "Symbol: %s = %x = %s, %d/%d\n", \
				sl+1, value, \
				(sym.size==0) ? symbol+1 : symbol, \
				sym.offset, sym.size);

		*kp = dlm;
		value = 2;
		if ( sym.size != 0 )
		{
			--value;
			++kp;
			elp += sprintf(elp, "+%d/%d", sym.offset, sym.size);
		}
		strncat(elp, kp, value);
		elp += value;
		sl = kp + value;
		if ( (kp = strstr(sl, "[<")) == (char *) 0 )
			strcat(elp, sl);
	}
	while ( kp != (char *) 0);
		
	if ( debugging )
		fprintf(stderr, "Expanded line: %s\n", el);
	return(el);
}


/*
 * Setting the -DTEST define enables the following code fragment to
 * be compiled.  This produces a small standalone program which will
 * echo the standard input of the process to stdout while translating
 * all numeric kernel addresses into their symbolic equivalent.
 */
#if defined(TEST)

#include <stdarg.h>

extern int main(int, char **);


extern int main(int argc, char *argv[])
{
	auto long int value;
	auto char line[1024], eline[2048];
	
	
#if 0
	value = atol(argv[1]);
	fprintf(stdout, "Value of %ld: %s\n", value, LookupSymbol(value));
#endif

	if ( !InitKsyms((char *) 0) )
	{
		fputs("ksym: Error loading system map.\n", stderr);
		return(1);
	}
	
	while ( !feof(stdin) )
	{
		gets(line);
		memset(eline, '\0', sizeof(eline));
		ExpandKadds(line, eline);
		fprintf(stdout, "%s\n", eline);
	}
	

	return(0);
}

extern void Syslog(int priority, char *fmt, ...)

{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stdout, "Pr: %d, ", priority);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);

	return;
}
#endif
