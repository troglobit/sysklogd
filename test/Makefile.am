EXTRA_DIST       = lib.sh opts.sh
EXTRA_DIST      += api.sh local.sh unicode.sh remote.sh fwd.sh mark.sh      \
		   memleak.sh facility.sh notify.sh rotate_all.sh secure.sh \
		   logger.sh
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
TESTS           += memleak.sh
TESTS           += mark.sh
TESTS           += notify.sh
TESTS           += rotate_all.sh
TESTS           += secure.sh

programs: $(check_PROGRAMS)
