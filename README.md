```
                  .--.  .--.              .--.
.-----.--.--.-----|  |--|  :-----.-----.--|  |
|__ --|  |  |__ --|    <|  |  _  |  _  |  _  |    RFC3164 :: syslogd for Linux
|_____|___  |_____|__|__|__|_____|___  |_____|    RFC5424 :: w/NetBSD syslogp()
      |_____|                    |_____|

<23>Aug 24 05:14:15 192.0.2.1 myproc[8710]: Kilroy was here.
<23>1 2019-11-04T00:50:15.001234+01:00 troglobit myproc 8710 - - Kilroy was here.
```
[![BSD Badge][]][BSD License] [![GitHub Status][]][GitHub] [![Coverity Status][]][Coverity Scan]

Table of Contents
-----------------

* [Introduction](#introduction)
* [Using -lsyslog](#using--lsyslog)
* [Build & Install](#build--install)
* [Building from GIT](#building-from-git)
* [Origin & References](#origin--references)

> **Tip:** the Gentoo project has a very nice article detailing sysklogd
> ➤ <https://wiki.gentoo.org/wiki/Sysklogd>


Introduction
------------

This is the continuation of the original Debian/Ubuntu syslog daemon,
updated with full [RFC3164][] and [RFC5424][] support from NetBSD and
FreeBSD.  The package includes the `libsyslog.{a,so}` library with a
`syslog.h` header replacement, the `syslogd` daemon, and a command
line tool called `logger`.

- https://man.troglobit.com/man1/logger.1.html
- https://man.troglobit.com/man8/syslogd.8.html
- https://man.troglobit.com/man5/syslog.conf.5.html

`libsyslog` and `syslog/syslog.h`, derived directly from NetBSD, expose
`syslogp()` and other new features available only in [RFC5424][]:

- https://man.troglobit.com/man3/syslogp.3.html
- https://netbsd.gw.com/cgi-bin/man-cgi?syslog+3+NetBSD-current

The `syslogd` daemon is an enhanced version of the standard Berkeley
utility program, updated with DNA from FreeBSD.  It provides logging of
messages received from the kernel, programs and facilities on the local
host as well as messages from remote hosts.  Although fully compatible
with standard C-library implementations of the `syslog()` API (GLIBC,
musl libc, uClibc), `libsyslog` must be used in your application to
unlock the new [RFC5424][] `syslogp()` API.

The included `logger` tool is primarily made for use with sysklogd, but
can be used stand-alone too.  It is not command line compatible with the
"standard" Linux logger tool from the bsdutils project.  Instead it is
compatible with the actual BSD logger tool(s) -- only major difference
is its support for `-I PID`, similar to the bsdutils `--id=PID`.  The
`logger` tool can be used from the command line, or script, to send both
RFC5424 (default) and old-style (BSD) RFC3164 formatted messages using
`libsyslog` to `syslogd` for local processing, or to a remote server.

Main differences from the original sysklogd package are:

- The separate `klogd` daemon is no longer part of the sysklogd project,
  syslogd now natively supports logging kernel messages as well
- *Major* command line changes to `syslogd`, for compatibilty with *BSD
- Supports `include /etc/syslog.d/*.conf` directive, see example .conf
- Built-in log-rotation support, with compression by default, useful for
  embedded systems.  No need for cron and/or a separate log rotate daemon
- Full [RFC3164][] and [RFC5424][] support from NetBSD and FreeBSD
- Support for sending RFC3164 style remote syslog messages, including
  timestamp and hostname.  Defaults to send w/o for compatibility
- Support for sending RFC5424 style remote syslog messages
- Support for sending messages to a custom port on a remote server
- Support for listening to a custom port
- Support for remote peer filtering, from FreeBSD
- Support for disabling DNS reverse lookups for each remote log message
- Support for FreeBSD Secure Mode, remote logging enabled by default(!)
- Includes a fit for purpose `logger` tool, compatible with `syslogd`,
  leveraging the full RFC5424 capabilities (`msgid` etc.)
- Includes a syslog library and system header replacement for logging
- FreeBSD socket receive buffer size patch
- Avoid blocking `syslogd` if console is backed up
- Touch PID file on `SIGHUP`, for integration with [Finit][]
- GNU configure & build system to ease porting/cross-compiling
- Support for configuring remote syslog timeout

Please file bug reports, or send pull requests for bug fixes and/or
proposed extensions at [GitHub][Home].


Using -lsyslog
--------------

libsyslog is by default installed as a library with a header file:

```C
#include <syslog/syslog.h>
```

The output from the `pkg-config` tool holds no surprises:

```sh
$ pkg-config --libs --static --cflags libsyslog
-I/usr/local/include -L/usr/local/lib -lsyslog
```

The prefix path `/usr/local/` shown here is only the default.  Use the
`configure` script to select a different prefix when installing libsyslog.

For GNU autotools based projects, instead of issuing the `pkg-config`
command manually, use the following in `configure.ac`:

```sh
# Check for required libraries
PKG_CHECK_MODULES([syslog], [libsyslog >= 2.0])
```

and for your "proggy" in `Makefile.am`:

```sh
proggy_CFLAGS = $(syslog_CFLAGS)
proggy_LDADD  = $(syslog_LIBS)
```

The distribution comes with an [example][] program that utilizes the
NetBSD API and links against libsyslog.


Build & Install
---------------

The GNU Configure & Build system use `/usr/local` as the default install
prefix.  In many cases this is useful, but this means the configuration
files and cache files will also use that same prefix.  Most users have
come to expect those files in `/etc/` and `/var/run/` and configure has
a few useful options that are recommended to use:

```sh
./configure --prefix=/usr --sysconfdir=/etc --runstatedir=/run
make -j5
sudo make install-strip
```

You may want to remove the `--prefix=/usr` option.  Most users prefer
non-distro binaries in `/usr/local` or `/opt`.

> **Note:** the `--runstatedir` option should point to a filesystem
>           that is cleaned at reboot.  syslogd relies on this for
>           its `syslogd.cache` file, which keeps track of the last
>           read kernel log message from `/dev/kmsg`.


Building from GIT
-----------------

If you want to contribute, or just try out the latest but unreleased
features, then you need to know a few things about the [GNU build
system][buildsystem]:

- `configure.ac` and a per-directory `Makefile.am` are key files
- `configure` and `Makefile.in` are generated from `autogen.sh`,
  they are not stored in GIT but automatically generated for the
  release tarballs
- `Makefile` is generated by `configure` script

To build from GIT you first need to clone the repository and run the
`autogen.sh` script.  This requires `automake` and `autoconf` to be
installed on your system.

```sh
git clone https://github.com/troglobit/sysklogd.git
cd sysklogd/
./autogen.sh
./configure && make
```

GIT sources are a moving target and are not recommended for production
systems, unless you know what you are doing!

**Note:** some systems may have an older, or a vanilla, version of the
  GNU autoconf package that does not support `--runstatedir` (above).
  Users on such systems are recommended to use `--localstatedir`, the
  `$runstatedir` used by sysklogd is derived from that if missing.


Origin & References
-------------------

This is the continuation of the original sysklogd by Dr. G.W. Wettstein
and [Martin Schulze][].  Currently maintained, and almost completely
rewritten by [Joachim Wiberg][], who spliced in fresh DNA strands from
the NetBSD and FreeBSD projects.  Much of the code base is NetBSD, but
the command line interface is FreeBSD.

> **Note:** the project name remains `sysklogd`, which was a combination
> of the names of the two main daemons, `syslogd` and `klogd`.  However,
> since v2.0 `klogd` no longer exists, kernel logging is now native to
> `syslogd`.

The project was previously licensed under the GNU GPL, but since the
removal of `klogd`, man pages, and resync with the BSDs the project is
now [3-clause BSD][BSD License] licensed.

[RFC3164]:          https://tools.ietf.org/html/rfc3164
[RFC5424]:          https://tools.ietf.org/html/rfc5424
[Martin Schulze]:   http://www.infodrom.org/projects/sysklogd/
[Joachim Wiberg]:   https://troglobit.com
[Finit]:            https://github.com/troglobit/finit
[Home]:             https://github.com/troglobit/sysklogd
[example]:          https://github.com/troglobit/sysklogd/tree/master/example
[buildsystem]:      https://airs.com/ian/configure/
[BSD License]:      https://en.wikipedia.org/wiki/BSD_licenses
[BSD Badge]:        https://img.shields.io/badge/License-BSD%203--Clause-blue.svg
[GitHub]:           https://github.com/troglobit/sysklogd/actions/workflows/build.yml/
[GitHub Status]:    https://github.com/troglobit/sysklogd/actions/workflows/build.yml/badge.svg
[Coverity Scan]:    https://scan.coverity.com/projects/19540
[Coverity Status]:  https://scan.coverity.com/projects/19540/badge.svg
