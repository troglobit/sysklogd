EXTRA_DIST       = lib.sh opts.sh
EXTRA_DIST      += api.sh local.sh unicode.sh remote.sh fwd.sh mark.sh      \
		   memleak.sh facility.sh notify.sh rotate_all.sh secure.sh \
		   logger.sh listen.sh sighup.sh tag.sh hostname.sh	    \
		   property.sh raw.sh regression.sh multicast.sh	    \
		    mcast-fwd.sh mcast-iface.sh
CLEANFILES       = *~ *.trs *.log
TEST_EXTENSIONS  = .sh
TESTS_ENVIRONMENT= unshare -mrun

check_PROGRAMS   = api
api_SOURCES      = api.c
api_CFLAGS       = -I$(srcdir)/../src
api_LDFLAGS      = -static
api_LDADD        = ../src/libsyslog.la

TESTS            = opts.sh
TESTS           += local.sh
TESTS           += logger.sh
TESTS           += unicode.sh
TESTS           += remote.sh
TESTS           += api.sh
TESTS           += facility.sh
TESTS           += fwd.sh
TESTS           += listen.sh
TESTS           += memleak.sh
TESTS           += mark.sh
TESTS           += notify.sh
TESTS           += rotate_all.sh
TESTS           += secure.sh
TESTS           += sighup.sh
TESTS           += tag.sh
TESTS           += hostname.sh
TESTS           += property.sh
TESTS           += raw.sh
TESTS           += regression.sh
TESTS           += multicast.sh
TESTS           += mcast-fwd.sh
TESTS           += mcast-iface.sh

programs: $(check_PROGRAMS)
