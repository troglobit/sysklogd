Structured Logging API
======================

The standard C-libraries in Linux ship only with the POSIX [`syslog(3)`][1]
family of APIs, but as of [RFC 5424][] the syslog protocol supports structured
logging, and this is what the custom API provides.

`libsyslog` is derived from NetBSD and exposes [`syslogp()`][2], and other
[RFC 5424][] features.  It carries a compatible `syslog()` API as well, so it
is safe to link against also for legacy applications.  The library has a
convenient `syslog.h` replacement.

The distribution comes with several [examples][] that all utilizes the library,
including the `syslogp(3)` API, and links against `libsyslog`.

Using `-lsyslog`
----------------

The following is taken from the `structured.c` example:

```C
#include <syslog/syslog.h>

int main(void)
{
    const char *msgid = "TLSEVENT";
    const char *sd    = "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\"]";

    openlog("structured", LOG_PID | LOG_PERROR, LOG_LOCAL0);
    syslogp(LOG_NOTICE, msgid, sd, "connection accepted from %s", "10.0.0.7");
    closelog();

    return 0;
}
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

[1]: https://man7.org/linux/man-pages/man3/syslog.3.html
[2]: https://man.troglobit.com/man3/syslogp.3.html
[RFC 5424]: https://tools.ietf.org/html/rfc5424
[examples]: examples/
