```
                  .--.  .--.              .--.
.-----.--.--.-----|  |--|  :-----.-----.--|  |
|__ --|  |  |__ --|    <|  |  _  |  _  |  _  |    RFC3164 :: syslogd for Linux
|_____|___  |_____|__|__|__|_____|___  |_____|    RFC5424 :: w/NetBSD syslogp()
      |_____|                    |_____|

<23>Aug 24 05:14:15 192.0.2.1 myproc[8710]: Kilroy was here.
<23>1 2019-11-04T00:50:15.001234+01:00 troglobit myproc 8710 - - Kilroy was here.
```
[![BSD Badge][]][BSD License] [![License Badge][]][License] [![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

Table of Contents
-----------------

* [Introduction](#introduction)
* [Using -lsyslog](#using--lsyslog)
* [Build & Install](#build--install)
* [Building from GIT](#building-from-git)
* [Origin & References](#origin--references)

Introduction
------------

This is the continuation of the original Debian/Ubuntu syslog daemon,
updated with full [RFC3164][] and [RFC5424][] support from NetBSD and
FreeBSD.  The package includes the `libsyslog.{a,so}` library and a
`syslog.h` header file replacement, two system log daemons, `syslogd`
and `klogd` (optional), and one command line tool called `logger`.

`libsyslog` and `syslog/syslog.h`, derived directly from NetBSD, expose
`syslogp()` and other new features available only in [RFC5424][]:

- https://netbsd.gw.com/cgi-bin/man-cgi?syslog+3+NetBSD-current

The `syslogd` daemon is an enhanced version of the standard Berkeley
utility program, updated with DNA from FreeBSD.  It is responsible for
providing logging of messages received from programs and facilities on
the local host as well as from remote hosts.  Although compatible with
standard C-library implementations of the `syslog()` API (GLIBC, musl
libc, uClibc), `libsyslog` must be used in your application to unlock
the new [RFC5424][] `syslogp()` API.

The optional `klogd` daemon, enabled with `configure --with-klogd`,
supports the GLIBC `klogctl()` API to read kernel log messages and can
also decode EIP addresses on Linux Oops, provided a `System.map` file.
The `syslogd` daemon can run stand-alone without `klogd`, this is the
default.

The included `logger` tool can be used from the command line, or script,
to send RFC5424 formatted messages using `libsyslog` to `syslogd` for
local or remote logging.

Main differences from the original sysklogd package are:

- `klogd` no longer built by default (optional) `syslogd` is stand-alone
- *Major* command line changes to `syslogd`, for compatibilty with *BSD
- Supports `include /etc/syslog.d/*.conf` directuve, see example .conf
- Built-in log-rotation support, with compression by default, useful for
  embedded systems.  No need for cron and a separate log rotate daemon
- Full [RFC3164][] and [RFC5424][] support from NetBSD and FreeBSD
- Support for sending RFC3164 style remote syslog messages, including
  timestamp and hostname.  Defaults to send w/o for compatibility
- Support for sending RFC5424 style remote syslog messages
- Support for sending messages to a custom port on a remote server
- Support for listening to a custom port
- Support for remote peer filtering, from FreeBSD
- Support for disabling DNS reverse lookups for each remote log message
- Support for FreeBSD Secure Mode
- Includes a `logger` tool with RFC5424 capabilities (`msgid` etc.)
- Includes a syslog library and system header replacement for logging
- FreeBSD socket receive buffer size patch
- Avoid blocking `syslogd` if console is backed up
- Touch PID file on `SIGHUP`, for integration with [Finit][]
- GNU configure & build system to ease porting/cross-compiling
- Support for configuring remote syslog timeout


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

For GNU autotools based projects, use the following in `configure.ac`:

```sh
# Check for required libraries
PKG_CHECK_MODULES([syslog], [libsyslog >= 2.0])
```

and in your `Makefile.am`:

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

    $ ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
    $ make -j5
    $ sudo make install-strip

You may want to remove the `--prefix=/usr` option.


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

    git clone https://github.com/troglobit/sysklogd.git
    cd sysklogd/
    ./autogen.sh
    ./configure && make

GIT sources are a moving target and are not recommended for production
systems, unless you know what you are doing!


Origin & References
-------------------

This is the continuation of the original sysklogd by Dr. G.W. Wettstein
and [Martin Schulze][].  Currently maintained, and heavily updated with
the latest features from NetBSD and FreeBSD, by [Joachim Nilsson][].
Please file bug reports, or send pull requests for bug fixes and
proposed extensions at [GitHub][].

The project is licensed under the [GPL][License], but the main `syslogd`
daemon and `syslogp()` API:s are [3-clause BSD][BSD License] licensed.

[RFC3164]:          https://tools.ietf.org/html/rfc3164
[RFC5424]:          https://tools.ietf.org/html/rfc5424
[Martin Schulze]:   http://www.infodrom.org/projects/sysklogd/
[Joachim Nilsson]:  http://troglobit.com
[Finit]:            https://github.com/troglobit/finit
[GitHub]:           https://github.com/troglobit/sysklogd
[example]:          https://github.com/troglobit/sysklogd/tree/master/example
[buildsystem]:      https://airs.com/ian/configure/
[License]:          https://en.wikipedia.org/wiki/GPL_license
[License Badge]:    https://img.shields.io/badge/License-GPL%20v2-blue.svg
[BSD License]:      http://en.wikipedia.org/wiki/BSD_licenses
[BSD Badge]:        https://img.shields.io/badge/License-BSD%203--Clause-blue.svg
[Travis]:           https://travis-ci.org/troglobit/sysklogd
[Travis Status]:    https://travis-ci.org/troglobit/sysklogd.png?branch=master
[Coverity Scan]:    https://scan.coverity.com/projects/19540
[Coverity Status]:  https://scan.coverity.com/projects/19540/badge.svg
