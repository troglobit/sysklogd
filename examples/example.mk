# Simple Makefile for the libsyslog example applications
# This is free and unencumbered software released into the public domain.

EXEC     := example basic structured reentrant multicast
CFLAGS   := `pkg-config --cflags libsyslog`
LDLIBS   := `pkg-config --libs --static libsyslog`

all: $(EXEC)

clean:
	$(RM) $(EXEC)

.PHONY: all clean
