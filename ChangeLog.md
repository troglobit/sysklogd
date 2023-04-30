Change Log
==========

All relevant changes to the project are documented in this file.


[v2.5.0][] - 2023-04-30
-----------------------

### Changes
- Issue #59: initial port to NuttX, contributed by Xiaomi
- Issue #61: add support for `-c` and `-cc` to disable log compression.
  A single `-c` disables compression for pipes, another `-c` (or `-cc`)
  disables compression for all other log targets
- The default `syslog.conf` now logs debug messages again (disabled in
  v2.4.0) due to problems (confusion) reported in the field
- Dropped not recommended `KillMode=process` from systemd unit file

### Fixes
- Issue #60: document how to set side-wide permissions on log files
- Issue #62: early log messages lost when running under systemd, found
  by Wind River Systems, including initial fix


[v2.4.4][] - 2022-08-14
-----------------------

### Fixes
- Fix #58: running syslogd with `-T` should use local time for remote
  messages, but time is always logged with "Jan 0 00:00:00".


[v2.4.3][] - 2022-08-12
-----------------------

### Changes
- Ensure output from `syslogd -v` and `logger -v` is the same, so
  that the project origin is the same, and that both use stdout

### Fixes
- Fix #57: garbled tag name in std (RFC3164) log file output


[v2.4.2][] - 2022-08-01
-----------------------

### Fixes
- Fix `logger` default severity, use **.notice**, like other logger
  implementations.  Was .info, which is of lesser severity, affecting
  some use-cases negatively (loss of logs)
- Drop extra leading space in log message in libsyslog RFC3164 format,
  two spaces between `proc[pid]:`, or plain `:`, and the message
- Drop trailing space in `logger` messages read from command line


[v2.4.1][] - 2022-08-01
-----------------------

### Changes
- Fake microsecond timestamp to allow for improved log sorting:
  - in RFC3164 messages (that don't have this resolution)
  - in untrusted kernel messages
- Dropped `debian/` directory (moved to separate branch), to ease
  re-packaging by downstream
- libsyslog now supports logging to remote servers, bypassing syslogd
- Major updates to `logger`:
  - Support for logging to a remote host, `-h HOST` and `-P PORT`
  - Support for logging in RFC3164 format, `-b`, mostly for remote
    logging to syslog servers that do not support RFC5424
  - Support for overriding hostname `-H NAME`
  - Support for custom PID, e.g., a shell scripts PID, `-I PID`

### Fixes
- Fix #52: Prevent over-read when scanning a new-style kernel message.
  Found and fixed by Edward K. McGuire
- Fix #53: prevent log file corruption when kernel messages contain
  control codes, notably `\n`.  Instead, preserve kernel protective
  C-style hex encoding.  For example, `\n` embedded in a message by a
  kernel-level facility is received as `\x0a`.  Found and fixed by
  Edward K. McGuire
- Fix #56: logging to remote machine stops after receiving a few
  SIGHUPs.  Open remote socket count was not reset properly on SIGHUP.
  Problem introduced in v2.4.0.  Reported by Edward K. McGuire
- Fix `gettimeofday()` error handling to use same fallback to `time()`
- Fix libsyslog opening and connecting to syslogd when `LOG_NLOG` is set
- Fix libsyslog so it honors `LOG_PTRIM` when logging to stderr
- Fix issue in RFC3164 output where the tag field could overflow.
  Spec. mandates tag never exceeds 32 characters

[v2.4.0][] - 2022-05-29
-----------------------

### Changes
- Add support for `secure_mode=[0,1,2]` to syslog.conf, same as `-s`
  but easier to use and activate with SIGHUP
- Enable `secure_mode=1` (only log to remote servers) in default `syslog.conf`
- Disable debug messages, in default `syslog.conf`, from `/var/log/syslog`
- Rename option `-K` to `-t` for trusting kernel timestamp, issue #42
- Add option `-K` to disable kernel logging, issue #48
- Rudimentary support for detecting if running in a container and then
  disable kernel logging automatically, issue #48
- Add support for `notify PATH` option to syslog.conf, for calling an
  external script on log rotation, by Steffen Nurpmeso, issue #45
- Add support for log rotation on SIGUSR2, by Steffen Nurpmeso, issue #46
- Update manual page for `-b` option description

### Fixes
- Issue #41: add missing `-H` option to usage text
- Issue #44: option misspelled in man page
- Issue #47: do not lose file mode on rotated files, by Steffen Nurpmeso
- Issue #48: verify kernel log FIFO is a proper character device, for
  running in certain container setups
- Issue #49: add support for `-8` command line option to allow 8-bit
  data to be logged -- this is a temporary fix until we have support
  for parsing the Unicode BOM, as defined in RFC5424
- Issue #50: fix issue with wall message, by Edward K. McGuire


[v2.3.0][] - 2021-11-27
-----------------------

### Changes
- Add support for `logger -k`, early log to `/dev/kmsg`.  Useful when
  logging from early system startup scripts before syslogd has started
- Support for extracting non-kernel log messages from `/dev/kmsg`
- Ignore `EINVAL` from kernel, caused warning message at first startup
- Use journald socket on systemd systems, not `/dev/log`
- Issue #38: add support for `syslogd -C file` to use `file` for caching
  the last seen kernel sequence number, default: `/run/syslogd.cache`.
  **Note:** syslogd relies on the location of this file to be wiped at
  system boot.  The default, `/run`, is a RAM disk on modern systems

### Fixes
- Issue #34: regression in v2.2.3, causing loss of syslogd log messages
  like `syslogd v2.2.3: restart.`
- Issue #35: man pages lists `-v` as verbose mode, is actually version
- Issue #36: retry DNS lookup of remote syslog servers with `res_init()`
  to ensure name resolution at bootup when a remote DNS may temporarily
  be unreachable.  Retry at most every five seconds, to prevent syslogd
  from monopolizing the CPU when emptying the kernel ring buffer
- Issue #39: update tests to use `-P fn` and `-C fn`
- Issue #40: improve documentation for syslogd.cache file requirements
- Issue #41: add missing documentation for -H option
- Issue #42: add option (`-K`) to always trust kernel timestamp.  By
  default `syslogd` only trusts the kernel timestamp for the initial
  emptying of the kernel ring buffer
- Issue #43: avoid asserting (exiting) on and around Jan 19, 2038, when
  the UNIX epoch wraps around on 32-bit `time_t` systems
- libsyslog: handle `EOVERFLOW` from `gettimeofday()` on Jan 19, 2038
- Avoid `NULL` pointers to internal `logit()` function, only triggered
  when in debug mode
- Replace `\m` with `\n` (missing newline) in `logger` usage text


[v2.2.3][] - 2021-05-11
-----------------------

Bug fix release.  The focus is still on tackling the fallout resulting
in migrating from the old kernel log interface in `/proc/kmsg` to
`/dev/kmsg`, introduced in v2.2.0.

### Fixes
- Issue #28: log messages stuck in 1969.  When not using libsyslog, or
  the bundled logger, the `syslog()` API in the C library is used, which
  may not necessarily set the timestamp.  When sysklogd infers timestamp
  it was offset by the number of years since 1969, i.e., `boot_time`
- Issue #29: kernel messages repeated if syslogd is restarted at runtime.
  This introduces a new state file, `/var/run/syslogd.cache`, which
  saves the last seen/logged sequence id read from `/dev/kmsg`
- Issue #31: log message time calculation issue on 32-bit systems
- Issue #32: remote kernel messages being mapped to uucp instead of user
- Fix `syslogd(8)` manual page name of the syslogd PID file


[v2.2.2][] - 2021-03-08
-----------------------

Bug fix release.

### Changes
- Load and reload timezone, with `tzset()`, on init/SIGHUP
- Logging from remote servers enabled by default in `syslogd.service`
  use `/etc/default/syslogd` to disable
- Initial Debian/Ubuntu packaging

### Fixes
- Fix issue with parsing /dev/kmsg time, off by one error
- Fix spelling issues in syslogd and man pages, found by lintian


[v2.2.1][] - 2021-01-30
-----------------------

Bug fix release.

### Fixes
- Issue #26: Liunx sends `EPIPE` when reading from `/dev/kmsg` if the
  kernel internal buffers are overrun.  `EPIPE` is a heads-up message to
  userspace that at least one log message has been lost.  Usually caused
  by a too small CONFIG_LOG_BUF_SHIFT value.  sysklogd v2.2.0 treated
  the descriptor as faulty and closed it.  The fix is to log the event
  and restart polling for more messages
- Issue #27: Linux log messages read from `/dev/kmsg` are formatted in a
  different way than its predecessor `/proc/kmsg`.  sysklogd v2.2.0
  failed to parse the priority field correctly, which caused matching
  problems with rules in `/etc/syslog.conf`
- Restore default install prefix, from `/` to `/usr/local`, which is
  the default for GNU configure based applications
- Drop `%m` gnuism from internal log macro (portability)
- logger: drop extra error message string, on error logging to a file


[v2.2.0][] - 2021-01-15
-----------------------

Minor feature and bug fix release.

### Changes
- Issue #19: use `/dev/kmsg` instead of `/proc/kmsg` on Linux

### Fixes
- Issue #17: Finally fix long-standing parallel build issue, thanks to
  Windriver for sticking with it and finding a really good fix!
- Issue #24: `O_CLOEXEC` not available on all systems
- Fix build error; allow loop initial declarations, enable C99
- Fix build warning; missing initializer for field 'usec'


[v2.1.2][] - 2020-03-22
-----------------------

Bug fix release.

### Fixes
- Issue #17: Windriver found and fixed a race between building lib/*.o
  files with and without `-fPIC`.  This should be the final parallel
  build issue.


[v2.1.1][] - 2020-01-19
-----------------------

Bug fix release.

### Changes
- Add unit test to verify rule option parsing
- Minor code cleanup and code de-duplication

### Fixes
- Issue #11: Some users still reported problems with parallel build,
  which was worked-around with `.NOTPARALLEL` in [v2.1][].  This v2 fix
  is a refactor of `src/Makefile.am` which removes `libcompat` and use
  the same objects for linking both `syslogd` and the user `libsyslog`
  API.  Yet still protecting against symbol poisoning
- A Westermo customer reported problems sending to remove syslog sinks
  at startup.  Turns out the handling if `sendmsg()` fails was the same
  as that if `syslogd` fails to resolve the IP from a DNS name.  The fix
  is to just let `sendmsg()` retry on the next syslog message for all
  benign/common network errors; `EHOSTUNREACHABLE`, `ENETUNREACH`, etc.
- Fix timer reset for suspended remote sinks.  For all new incoming syslog
  messages all suspended (remote) sinks had their timeout mistakenly reset


[v2.1][] - 2020-01-05
---------------------

Relicensed under the 3-clause BSD license.

### Changes
- `klogd` removed, replaced by native `syslogd` functionality
- Import pristine FreeBSD versions of `syslogd` and `syslog.conf` man
  pages, both under the 3-clause BSD license.
- With `klogd` removed and the original man pages replaced with FreeBSD
  versions, the only remaining GPL'ed material was the build system,
  which the copyright owner (undersigned) agrees to change to BSD as
  well.  Hence, the GNU GPL could be dropped in favor of 3-clause BSD

### Fixes
- Issue #8: Kernel messages duplicated to console.  `syslogd` on Linux
  now calls `klogctl()` to disable kernel logging to console
- Earlier versions were slightly sensitive to time skips.  I.e., when
  recording the last-change time on a log file and wall time changed
  backwards, `syslogd` would consider that log file to have a date in
  the future.  This only affected buffering of multiple messages, and
  `-- MARK --` so most users never would have noticed
- Issue #9: Kernel logging broken if `syslogd` started without `-F`
- Issue #10: Fix build on non-GLIBC Linux systems, by Khem Raj
- Issue #11: Fix nasty parallel build problem.  Also reported by the
  Gentoo project, and Westermo
- Make sure log rotation cannot be enabled for non-file targets
- Use `snprintf()` rather than `sprintf()` in log rotation
- Fix variable names shadowing global/local defs, found by clang-tidy
- Handle multiple invocations of SIGHUP, respond to all of them
- Use correct `#ifdef` for checking on Linux or not


[v2.0.3][] - 2019-12-01
-----------------------

### Changes
- Always run `domark()` timer, regardless of `-m interval` setting,
  it is used for internal housekeeping, runs every 15 sec
- Handle DNS lookup of unknown remote syslog hosts in `domark()`
- Only enable debug mode when `-d` is given on the command line
- Always create PID file, even in debug mode
- Add `-F`, as alias for `-n`, to klogd for compat. with syslogd

### Fixes
- When logging to a remote host using @FQDN previous releases of syslogd
  gave up after 10 tries.  In many industrial cases intermittent access
  to the DNS is very likely, so this release includes a fix to retry the
  IP address lookup forever.  The interval for retries is configurable
- Fix accidental blocking of SIGHUP/SIGALRM when an invalid facility is
  found in the internal `logmsg()` function
- Fix leaking of internal error messages (like DNS lookup failure) to
  `/dev/console` during reconfiguration, i.e. after initial start


[v2.0.2][] - 2019-11-28
-----------------------

### Changes
- Add missing remote:port info in error message when failing to send to
  a remote syslog server.

### Fixes
- Fix `assert()` in `fprintlog_successive()`, caused by never being
  reset in `fprintlog_first()`, found by Westermo
- Issue #6: Workaround for systems with vanilla autoconf 2.69 that does
  not support `--runstatedir=PATH`, e.g. CRUX <https://crux.nu/>


[v2.0.1][] - 2019-11-25
-----------------------

Minor bug fix release.

### Changes
- Make logger tool and man page optional in build, by Lars Wendler
- Expand resulting directories in configure summary

### Fixes
- Add missing `-k` and `-T` command line flags to `getopt()`
- Issue #3: Don't guess PID file location, use configre's `$runstatedir`


[v2.0][] - 2019-11-15
---------------------

This release represents a major refresh of the sysklogd project.  The
venerable syslogd gets an infusion of new blood from NetBSD and FreeBSD
to fully support RFC3164 and RFC5424.  Also included is a user library
and a replacement for `syslog.h` to enable new features in RFC5424.

> Note: as of this release `klogd` is disabled by default, `syslogd` can
>       read Linux kernel messages on its own now.

### Changes
- Support for true RFC3164 formatted log messages to remote log servers,
  including timestamp and hostname.  Use `;RFC3164` rule option
- Support for RFC5424 from UNIX domain socket, from remote servers and also
  to remote servers.  Requires new API `syslogp()` to unlock these features
  on the UNIX socket.  Still compatible with GLIBC/musl/uClibc
- Support for options to `syslog.conf` rules.  E.g. `;RFC5424` to enable
  sending/writing log messages with RFC3339 style timestamps, and more
- Support for `include /etc/syslog.d/*.conf` in `syslog.conf`
- New tool `logger` from the Finit project, BSD licensed.  Supports all the
  features of RFC5424, so *very* useful for trying out the "new" standard
- Support for reading from a custom UNIX domain socket path, `-p SOCK`,
  for unit testing with `logger -u /path/to/sock`
- Support for sending to a custom port on a remote server, `@host:port`
- New `syslogp()` API from NetBSD, for applications wanting to use
  RFC5424 features like MsgID or structured data
- Many *incompatible changes* to command line options in `syslogd` and
  `klogd` for compatiblity with FreeBSD and NetBSD syslogd.  Examples:
  - In syslogd: `-b` and `-c` have been replaced with `-r` for global
    log rotation, `-a` has been replaced with the new `-p` support.  The
    `-r` flag and `-s HOST` has also been dropped in favor of the BSD
    `-s` flag to control two levels of _secure mode_.  The `-n` flag is
	now `-F` and `-n` means something else entirely ... there's more
  - In klogd: `-i` and `-I` have been removed
- `klogd` is not built by default anymore, `syslogd` can read `/proc/kmsg`
  on Linux on its own.  Reduces complexity and gives you one daemon less
- When systemd support is detected by the configure script the unit file(s)
  are now installed into the systemd system services folder
- Update COPYING file to GPL 2 rev 2, with new FSF address and other minor stuff
- Update license header in all files:
  - Sync 3-clause BSD license change with upstream NetBSD and FreeBSD sources
  - Sync GPL license header, new FSF address
  - Add SPDX license identifiers to all source files

### Fixes
- Fix GCC 8 warnings; "too small destination buffer in `snprintf()`"
- Major code cleanup and rewrite inspired by both NetBSD and FreeBSD
  sources, e.g. removed all previous unit `TESTING` #ifdefs


[v1.6][] - 2018-09-25
---------------------

### Changes
- IPv6 support forward ported from FreeBSD, by John Haxby <john.haxby@oracle.com>
- Built-in log rotation support from BusyBox syslogd, disabled by default
  - Enable from command line using '-b SIZE' and '-c COUNT', or
  - Per log file in syslog.conf using 'SIZE:COUNT'
- Automatic compression (gzip) of rotated files from .1
- Only read /etc/services when needed, by Martin Schulze <joey@infodrom.org>
- Improved sleep/alarm/mark implementation,  
  by Alan Jenkins <alan-jenkins@tuffmail.co.uk>
- Move hostname setting code from `main()` into `init()` so it is
  re-read on SIGHUP, by Thomas Jarosch <thomas.jarosch@intra2net.com>
- Documentation update by Martin Schulze <joey@infodrom.org>
- Re-indent code to Linux KNF
- Touch PID file on `SIGHUP`, for integration with Finit
- Add systemd unit files
- Add GNU configure & build system
  - Add configure flags to enable features and control behavior
  - Detect systemd PATHs

### Fixes
- Flush log files independent of MARK, by Martin Schulze <joey@infodrom.org>
- Fix segfault, remove faulty `fclose()`, found by Andrea Morandi and
  Sean Young.  Fixed by Martin Schulze <joey@infodrom.org>
- Correct continuation line problems on 64bit architecture,  
  by David Couture <glowplugrelayw0rks@gmail.com>
- Bugfix against invalid PRI values (CVE-2014-3634), by mancha <mancha1@zoho.com>
- Ignore backed up (low baud rate) console, and do not close it.
  Instead, continue writing when its unclogged
- Increase socket receive buffer size (double), patch from FreeBSD


[v1.5.1][] - 2014-10-06
-----------------------

### Fixes
- Bugfix against invalid PRI values (CVE-2014-3634), by mancha <mancha1@zoho.com>


[v1.5][] - 2007-07-27
---------------------

- Dmitry V. Levin <ldv@altlinux.org>
   - Close file descriptor in FindSymbolFile() in ksym.c in order not to
     leak file descriptors.
- Solar Designer <solar@openwall.com>
   - improve crunch_list()
   - Prevent potential buffer overflow in reading messages from the
     kernel log ringbuffer.
   - Ensure that "len" is not placed in a register, and that the
     endtty() signal handler is not installed too early which could
     cause a segmentation fault or worse.
- Steve Grubb <linux_4ever@yahoo.com>
   - fix memory calculation in crunch_list()
- Martin Schulze <joey@infodrom.org>
   - klogd will reconnect to the logger (mostly syslogd) after it went
     away
   - On heavily loaded system syslog will not spit out error messages
     anymore when recvfrom() results in EAGAIN
   - Makefile improvements
   - Local copy of module.h
   - Improved sysklogd.8
   - Always log with syslogd's timezone and locale
   - Remove trailing newline when forwarding messages
   - Continue working properly if /etc/service is missing and ignore
     network activity
   - Continue writing to log files as soon as space becomes available
     again after a filled up disk
   - Removed test to detect control characters > 0x20 as this prevented
     characters encoded in UTF-8 to be properly passed through
   - Only resolve the local domain when accepting messages from remote
   - Properly accompany the MARK message with the facility
   - Improved daemonise routine in klogd to stabilise startup
   - klogd will not change the console log level anymore unless -c is given
   - Added back /usr/src/linux/System.map as fall-back location
   - Rewrote the module symbol parser to read from /proc/kallsyms
   - Notify the waiting parent process if the client dies so it doesn't
     wait the entire five minutes.
   - Complete rewrite of the oops kernel module for Linux 2.6
   - Only read kernel symbols from /proc/kallsyms if no System.map has been read
   - Improved symbol lookup
   - Prevent named pipes from becoming the controlling tty
- Jon Burgess <Jon_Burgess@eur.3com.com>
   - Moved the installation of the signal handler up a little bit so it
     guaranteed to be available when the child is forked, hence, fixing a
     race condition.  This used to create problems with UML and fast
     machines.
- Greg Trounson <gregt@maths.otago.ac.nz>
   - Improved README.linux
- Ulf Härnhammar <Ulf.Harnhammar.9485@student.uu.se>
   - Boundary check for fscanf() in InitKsyms() and CheckMapVersion()
- Colin Phipps <cph@cph.demon.co.uk>
   - Don't block on the network socket in case of packet loss
- Dirk Mueller <mueller@kde.org>
   - Don't crash when filesize limit is reached (e.g. without LFS)
- Miquel van Smoorenburg <miquels@cistron.nl>
   - Fix spurious hanging syslogd in connection with futex and NPTL
     introduced in recent glibc versions and Linux 2.6
     (Details: http://bugs.debian.org/301511)
- Eric Tucker <et@tallmaple.com>
   - Improved syslog.conf(5) manpage
- Mike Frysinger <vapier@gentoo.org>
   - use socklen_t where appropriate
- Kelledin <kelledin@skarpsey.dyndns.org>
   - use newer query_module function rather than stepping through /dev/kmem.
- Matthew Fischer <futhark@vzavenue.net>
   - Remove special treatment of the percent sign in klogd


[v1.4.1][] - 2001-03-11
-----------------------

- klogd will set the console log level only if `-c' is given on the
   commandline, not overwriting local settings in `/etc/sysctl.conf'.
- Bugfix: klogd will use SOCK_DGRM as well, re-enables kernel logging
- Bugfix: Don't make syslogd fail with broken `-a'
- Bugfix: klogd will skip zero bytes and not enter a busy loop anymore
- Thomas Roessler <roessler@does-not-exist.org>
   - Patch to prevent LogLine() from being invoked with a negative
     counter as an argument.


[v1.4][] - 2000-09-19
---------------------

- Skip newline when reading in klog messages
- Use lseek64() instead of llseek() which is deprecated these days
- Close symbol file before returning with 0 when an error occurred
   while reading it.  This will enable systems to umount that
   partition with no open file descriptor left over.
- Solar Designer <solar@false.com>
   - printline() fixes
   - priority decoding fix
- Daniel Jacobowitz <dan@debian.org>
   - printchopped() fix
- Keith Owens <kaos@ocs.com.au>
   - Fixed bug that caused klogd to die if there is no sym_array available.
   - When symbols are expanded, print the line twice.  Once with
     addresses converted to symbols, once with the raw text.  Allows
     external programs such as ksymoops do their own processing on the
     original data.
- Olaf Kirch <okir@caldera.de>
   - Remove Unix Domain Sockets and switch to Datagram Unix Sockets
- Several bugfixes and improvements, please refer to the .c files


[UNRELEASED]: https://github.com/troglobit/sysklogd/compare/v2.5.0...HEAD
[v2.5.0]:     https://github.com/troglobit/sysklogd/compare/v2.4.4...v2.5.0
[v2.4.4]:     https://github.com/troglobit/sysklogd/compare/v2.4.3...v2.4.4
[v2.4.3]:     https://github.com/troglobit/sysklogd/compare/v2.4.2...v2.4.3
[v2.4.2]:     https://github.com/troglobit/sysklogd/compare/v2.4.1...v2.4.2
[v2.4.1]:     https://github.com/troglobit/sysklogd/compare/v2.4.0...v2.4.1
[v2.4.0]:     https://github.com/troglobit/sysklogd/compare/v2.3.0...v2.4.0
[v2.3.0]:     https://github.com/troglobit/sysklogd/compare/v2.2.3...v2.3.0
[v2.2.3]:     https://github.com/troglobit/sysklogd/compare/v2.2.2...v2.2.3
[v2.2.2]:     https://github.com/troglobit/sysklogd/compare/v2.2.1...v2.2.2
[v2.2.1]:     https://github.com/troglobit/sysklogd/compare/v2.2.0...v2.2.1
[v2.2.0]:     https://github.com/troglobit/sysklogd/compare/v2.1.2...v2.2.0
[v2.1.2]:     https://github.com/troglobit/sysklogd/compare/v2.1.1...v2.1.2
[v2.1.1]:     https://github.com/troglobit/sysklogd/compare/v2.1...v2.1.1
[v2.1]:       https://github.com/troglobit/sysklogd/compare/v2.0.3...v2.1
[v2.0.3]:     https://github.com/troglobit/sysklogd/compare/v2.0.2...v2.0.3
[v2.0.2]:     https://github.com/troglobit/sysklogd/compare/v2.0.1...v2.0.2
[v2.0.1]:     https://github.com/troglobit/sysklogd/compare/v2.0...v2.0.1
[v2.0]:       https://github.com/troglobit/sysklogd/compare/v1.6...v2.0
[v1.6]:       https://github.com/troglobit/sysklogd/compare/v1.5...v1.6
[v1.5.1]:     https://github.com/troglobit/sysklogd/compare/v1.5...v1.5.1
[v1.5]:       https://github.com/troglobit/sysklogd/compare/v1.4...v1.5
[v1.4]:       https://github.com/troglobit/sysklogd/compare/v1.3...v1.4
