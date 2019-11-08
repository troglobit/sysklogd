Stand-alone Example syslogp() Application
=========================================

This is a *very* simple stand-alone example application.  The purpose is
to show how to use the sysklogd 2.x API, e.g. `syslogp()`, to use "new"
RFC5424 features like MsgID.

Included in this directory are two files:

 - `example.c`: actual C code example
 - `example.mk`: plain Makefile for building `example`

Provided the two files are in the same (writable) directory, you can
build the application like this:

    make -f example.mk


GNU Autotools
-------------

If you want to use GNU autoconf & automake instead.  The following is
recommended in `configure.ac` and `Makefile.am` to build your
application.

```sh
# configure.ac (snippet)

# Check for pkg-config tool, required for next step
PKG_PROG_PKG_CONFIG

# Check for required libraries
PKG_CHECK_MODULES([syslog], [libsyslog >= 2.0])
```

and

```Makefile
# Makefile.am (snippet)

bin_PROGRAMS    = example

example_SOURCES = example.c
example_CFLAGS  = $(syslog_CFLAGS)
example_LDADD   = $(syslog_LIBS)
```

**NOTE:** Most free/open source software that uses `configure` default
  to install to `/usr/local`.  However, some Linux distributions do no
  longer search that path for installed software, e.g. Fedora and Alpine
  Linux.  To help your configure script find its dependencies you have
  to give the `pkg-config` a prefix path:

    PKG_CONFIG_LIBDIR=/usr/local/lib/pkgconfig ./configure


License
-------

This example code, `example.c`, this README.md and the `example.mk`
Makefile are free and unencumbered software released into the public
domain.

