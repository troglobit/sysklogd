EXTRA_DIST       = test.rc start.sh stop.sh
EXTRA_DIST      += api.sh local.sh remote.sh
CLEANFILES       = *~ *.trs *.log
TEST_EXTENSIONS  = .sh

check_PROGRAMS   = api
api_SOURCES      = api.c
api_CFLAGS       = -I$(srcdir)/../src
api_LDFLAGS      = -static
api_LDADD        = ../src/libsyslog.la

TESTS            = start.sh
TESTS           += local.sh
TESTS           += remote.sh
TESTS           += api.sh
TESTS           += stop.sh

programs: $(check_PROGRAMS)
