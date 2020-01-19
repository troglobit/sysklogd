EXTRA_DIST       = test.rc opts.sh start.sh stop.sh
EXTRA_DIST      += api.sh local.sh remote.sh fwd.sh mark.sh
CLEANFILES       = *~ *.trs *.log
TEST_EXTENSIONS  = .sh

check_PROGRAMS   = api
api_SOURCES      = api.c
api_CFLAGS       = -I$(srcdir)/../src
api_LDFLAGS      = -static
api_LDADD        = ../src/libsyslog.la

TESTS            = opts.sh
TESTS           += start.sh
TESTS           += local.sh
TESTS           += remote.sh
TESTS           += api.sh
TESTS           += fwd.sh
TESTS           += mark.sh
TESTS           += stop.sh

programs: $(check_PROGRAMS)
