# Makefile for syslogd and klogd daemons.

CC= gcc
#CFLAGS= -g -DSYSV -Wall
#LDFLAGS= -g
CFLAGS= -O6 -DSYSV -fomit-frame-pointer -Wall
LDFLAGS= -s -N

# Look where your install program is
#
INSTALL = /usr/bin/install
BINDIR = /usr/sbin
MANDIR = /usr/man

# There is one report that under an all ELF system there may be a need to
# explicilty link with libresolv.a.  If linking syslogd fails you may wish
# to try uncommenting the following define.
# LIBS = /usr/lib/libresolv.a

# Define the following to impart start-up delay in klogd.  This is
# useful if klogd is started simultaneously or in close-proximity to syslogd.
# KLOGD_START_DELAY = -DKLOGD_DELAY=5

# The following define determines whether the package adheres to the
# file system standard.
FSSTND = -DFSSTND

# The following define establishes ownership for the man pages.
# Avery tells me that there is a difference between Debian and
# Slackware.  Rather than choose sides I am leaving it up to the user.
MAN_OWNER = root
# MAN_OWNER = man

# The following define establishes the name of the pid file for the
# syslogd daemon.  The library include file (paths.h) defines the
# name for the syslogd pid to be syslog.pid.  A number of people have
# suggested that this should be syslogd.pid.  You may cast your
# ballot below.
# SYSLOGD_PIDNAME = -DSYSLOGD_PIDNAME=\"syslogd.pid\"

SYSLOGD_FLAGS= -DSYSLOG_INET -DSYSLOG_UNIXAF -DNO_SCCS ${FSSTND} \
	${SYSLOGD_PIDNAME}
SYSLOG_FLAGS= -DALLOW_KERNEL_LOGGING
KLOGD_FLAGS = ${FSSTND} ${KLOGD_START_DELAY}

.c.o:
	${CC} ${CFLAGS} -c $*.c

all:	syslogd	klogd syslog_tst

install: install_man install_exec

syslogd: syslogd.o pidfile.o
	${CC} ${LDFLAGS} -o syslogd syslogd.o pidfile.o ${LIBS}

klogd:	klogd.o syslog.o pidfile.o ksym.o
	${CC} ${LDFLAGS} -o klogd klogd.o syslog.o pidfile.o ksym.o

syslog_tst: syslog_tst.o
	${CC} ${LDFLAGS} -o syslog_tst syslog_tst.o

syslogd.o: syslogd.c version.h
	${CC} ${CFLAGS} ${SYSLOGD_FLAGS} -c syslogd.c

syslog.o: syslog.c
	${CC} ${CFLAGS} ${SYSLOG_FLAGS} -c syslog.c

klogd.o: klogd.c klogd.h version.h
	${CC} ${CFLAGS} ${KLOGD_FLAGS} -c klogd.c

ksym.o: ksym.c klogd.h
	${CC} ${CFLAGS} ${KLOGD_FLAGS} -c ksym.c

syslog_tst.o: syslog_tst.c
	${CC} ${CFLAGS} -c syslog_tst.c

clean:
	rm -f *.o *.log *~ *.orig;

clobber: clean
	rm -f syslogd klogd syslog_tst TAGS;

install_exec: syslogd klogd
	${INSTALL} -m 500 -s syslogd ${BINDIR}/syslogd;
	${INSTALL} -m 500 -s klogd ${BINDIR}/klogd;

install_man:
	${INSTALL} -o ${MAN_OWNER} -g ${MAN_OWNER} -m 644 sysklogd.8 ${MANDIR}/man8/sysklogd.8
	${INSTALL} -o ${MAN_OWNER} -g ${MAN_OWNER} -m 644 syslogd.8 ${MANDIR}/man8/syslogd.8
	${INSTALL} -o ${MAN_OWNER} -g ${MAN_OWNER} -m 644 syslog.conf.5 ${MANDIR}/man5/syslog.conf.5
	${INSTALL} -o ${MAN_OWNER} -g ${MAN_OWNER} -m 644 klogd.8 ${MANDIR}/MAN8/klogd.8
