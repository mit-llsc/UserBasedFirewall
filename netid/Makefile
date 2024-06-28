CC = /usr/bin/gcc
RM = /bin/rm
STRIP = /usr/bin/strip
KERNINCLUDE = -I/usr/src/linux-headers-4.15.0-43/include

ifeq ($(PREFIX),)
    PREFIX := /usr
endif

TARGETS = netidd
TARGETBINS = netidd

CFLAGS = -O3 -Wall -std=c99 -g -I.
LFLAGS = -lnfnetlink -lnetfilter_queue -lrt -lcap

all: $(TARGETS)

netidd:
	$(CC) $(CFLAGS) netidd.c log.c config.c -o netidd $(LFLAGS)
	strip --strip-debug --strip-unneeded netidd

netidd-debug:
	$(CC) $(CFLAGS) netidd.c log.c config.c -o netidd $(LFLAGS)
	objcopy --only-keep-debug netidd netidd.debug
	strip --strip-debug --strip-unneeded netidd
	objcopy --add-gnu-debuglink=netidd.debug netidd

.PHONY: install
install: $(TARGETS)
	install -m 0755 -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(TARGETBINS) $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 -d $(DESTDIR)/etc/systemd/system
	install -m 0644 netidd.service $(DESTDIR)/etc/systemd/system
	install -m 0644 netidd.conf $(DESTDIR)/etc/netidd.conf

clean:
	$(RM) -rf netidd netidd.debug debian/netidd* debian/.debhelper

deb:
	dpkg-buildpackage -b -rfakeroot -us -uc
