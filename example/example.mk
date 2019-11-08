# Simple Makefile for syslogp() example application
# This is free and unencumbered software released into the public domain.

EXEC     := example
OBJS     := example.o
CFLAGS   := `pkg-config --cflags libsyslog`
LDLIBS   := `pkg-config --libs --static libsyslog`

all: $(EXEC)

$(EXEC): $(OBJS)
