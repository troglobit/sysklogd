Change Log
==========

All relevant changes to the project are documented in this file.

[v1.6][UNRELEASED]
------------------

### Changes
- IPv6 support forward ported from FreeBSD, by John Haxby <john.haxby@oracle.com>
- Built-in log rotation support from BusyBox syslogd, disabled by default
- Automatic compression (gzip) of rotated files from .1
- Only read /etc/services when needed, by Martin Schulze <joey@infodrom.org>
- Improved sleep/alarm/mark implementation,  
  by Alan Jenkins <alan-jenkins@tuffmail.co.uk>
- Move hostname setting code from `main()` into `init()`,  
  by Thomas Jarosch <thomas.jarosch@intra2net.com>
- Documentation update by Martin Schulze <joey@infodrom.org>
- Reindent code to Linux KNF
- Touch PID file on `SIGHUP`, for integration with Finit
- Add systemd unit files
- Add GNU configure & build system
  - Add configure flags to enable features and control behavior
  - Detect systemd PATHs

### Fixes
- Correct continuation line problems on 64bit architecture,  
  by David Couture <glowplugrelayw0rks@gmail.com>
- Bugfix against invalid PRI values (CVE-2014-3634), by mancha <mancha1@zoho.com>


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


[UNRELEASED]: https://github.com/troglobit/sysklogd/compare/v1.5...HEAD
[v1.6]:       https://github.com/troglobit/sysklogd/compare/v1.5...v1.6
[v1.5.1]:     https://github.com/troglobit/sysklogd/compare/v1.5...v1.5.1
[v1.5]:       https://github.com/troglobit/sysklogd/compare/v1.4...v1.5
[v1.4]:       https://github.com/troglobit/sysklogd/compare/v1.3...v1.4
