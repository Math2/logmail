CC ?= cc
CFLAGS ?= -O2 -pipe -Wall
INSTALL ?= install
PREFIX ?= /usr/local

all: logmail # logstamp

clean:
	rm -f logmail # logstamp

logmail: logmail.c
	$(CC) $(CFLAGS) -o $@ logmail.c

logstamp: logstamp.c
	$(CC) $(CFLAGS) -o $@ logstamp.c

install: logmail
	mkdir -p "$(PREFIX)/bin"
	$(INSTALL) -m 755 logmail "$(PREFIX)/bin/logmail"
