# Simple Makefile for syslogp() example application
#
EXEC     := example
OBJS     := example.o
CFLAGS   := `pkg-config --cflags libsyslog`
LDLIBS   := `pkg-config --libs --static libsyslog`

all: $(EXEC)

$(EXEC): $(OBJS)
