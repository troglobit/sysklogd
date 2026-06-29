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

> [!TIP]
> The Gentoo project has a very nice article detailing sysklogd
> ➤ <https://wiki.gentoo.org/wiki/Sysklogd>

Introduction
------------

This is the continuation of the original Debian/Ubuntu syslog daemon, updated to
full RFC compliance according to syslog standards [RFC3164][] and [RFC5424][],
derived from NetBSD and FreeBSD.  It also supports TCP ([RFC6587][]) and TLS
encrypted transport ([RFC5425][]), as well as cryptographically signed log
messages ([RFC5848][]).

The package includes the `libsyslog.{a,so}` library (a `syslog.h` replacement),
the `syslogd` daemon, and a `logger` command line tool.  `syslogd` logs messages
from the kernel, local programs, and remote hosts.  `libsyslog` is derived from
NetBSD and exposes `syslogp()` and other [RFC5424][] features not yet in GLIBC;
it is compatible with the standard `syslog()` API (GLIBC, musl, uClibc), but an
application must link `libsyslog` to use `syslogp()`.

Read more about each component and the APIs:

- <https://man.troglobit.com/man1/logger.1.html>
- <https://man.troglobit.com/man8/syslogd.8.html>
- <https://man.troglobit.com/man5/syslog.conf.5.html>
- <https://man.troglobit.com/man3/syslogp.3.html>
- <https://netbsd.gw.com/cgi-bin/man-cgi?syslog+3+NetBSD-current>

The bundled `logger` sends RFC5424 (default) or RFC3164 messages to a local or
remote `syslogd`.  Its command line follows the BSD `logger`, not the bsdutils
one (it adds `-I PID`, cf. bsdutils `--id=PID`).

Main differences from the original sysklogd package:

- Transports and remote logging: UDP, TCP ([RFC6587][]), and TLS
  ([RFC5425][], with OpenSSL), for both sending and receiving, on a
  configurable port; RFC3164 or RFC5424 framing (RFC3164 sent without
  timestamp/hostname by default, for compatibility); multicast groups, IPv4
  and IPv6; cryptographically signed messages ([RFC5848][], with OpenSSL); a
  per-destination in-memory TCP send queue that buffers during an outage and
  flushes on reconnect (`tcp_suspend_time`); a configurable remote timeout;
  FreeBSD-style remote peer filtering; and FreeBSD Secure Mode.
- Filtering and configuration: FreeBSD-style property-based filtering, by
  host, program, regexp, or substring; OpenBSD-style stop-processing prefixes
  (`!!prog`, `++host`, `::filter`) that capture a message exclusively;
  `include /etc/syslog.d/*.conf`; and per-message DNS reverse-lookup control.
- Operation: native kernel logging, no separate `klogd`; built-in log
  rotation with compression; non-blocking when the console is backed up; the
  FreeBSD socket-receive-buffer patch; and a PID file touched on `SIGHUP`, for
  [Finit][] integration.
- Compatibility and build: a major, *BSD-compatible `syslogd` command line;
  the bundled `logger` (RFC5424 `msgid`, UDP/TCP/TLS, and a `-V` verify mode);
  the `libsyslog` library and `syslog.h` replacement; and a GNU configure/build
  system for porting and cross-compiling.

Please file bug reports, or send pull requests for bug fixes and/or
proposed extensions at [GitHub][Home].


Using -lsyslog
--------------

libsyslog is by default installed as a library with a header file:

```C
#include <syslog/syslog.h>
```

Query the build flags with `pkg-config`:

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

After editing the configuration, reload `syslogd` to apply it:
`kill -HUP $(cat /run/syslogd.pid)`, or `systemctl reload syslogd`.  See
`syslog.conf(5)` for the file format.


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
[RFC5425]:          https://tools.ietf.org/html/rfc5425
[RFC5848]:          https://tools.ietf.org/html/rfc5848
[RFC6587]:          https://tools.ietf.org/html/rfc6587
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
