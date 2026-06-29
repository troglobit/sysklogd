Stand-alone syslogp() Examples
=============================

These are small, stand-alone examples of the sysklogd `libsyslog` API,
including the "new" RFC5424 features (MSGID and structured data) exposed
by `syslogp()`.

Included in this directory, each demonstrating one part of the API:

- `example.c`: minimal `syslogp()` call, start here
- `basic.c`: classic `syslog()`, `openlog()` flags, priority mask, `%m`
- `structured.c`: RFC5424 MSGID and a structured-data (SD) element
- `reentrant.c`: thread-safe `*_r` API with a local `struct syslog_data`
- `multicast.c`: forwarding to a multicast group via `log_host`,
  `log_iface`, and `log_ttl`
- `example.mk`: plain Makefile that builds them all

Provided the files are in the same (writable) directory, build them all
with:

```sh
$ make -f example.mk
...
```

or build a single one, e.g. `make -f example.mk structured`.  The
`LOG_STDOUT` flag in several of them prints the formatted message to
stdout, so they show output without a running `syslogd`.

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

```sh
$ PKG_CONFIG_LIBDIR=/usr/local/lib/pkgconfig ./configure
...
```

License
-------

These examples, this README.md and the `example.mk` Makefile are free
and unencumbered software released into the public domain.
