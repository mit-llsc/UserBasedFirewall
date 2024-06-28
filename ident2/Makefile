CC = /usr/bin/gcc
RM = /bin/rm
STRIP = /usr/bin/strip

ifeq ($(PREFIX),)
    PREFIX := /usr
endif

CFLAGS = -O3 -Wall -std=c99 -g -I.
LFLAGS = -lnfnetlink -lrt -lcap -lpthread

TARGETBINS = ident2d
TARGETLIBS = libident2_precache.so

all: ident2d

ident2d:
	$(CC) $(CFLAGS) ident2d.c log.c findsocket.c config.c -o ident2d $(LFLAGS)
	$(CC) $(CFLAGS) -shared -fPIC ident2_precache.c -o libident2_precache.so
	$(STRIP) --strip-debug --strip-unneeded ident2d libident2_precache.so

ident2d-debug:
	$(CC) $(CFLAGS) ident2d.c log.c findsocket.c config.c -o ident2d $(LFLAGS)
	objcopy --only-keep-debug ident2d ident2d.debug
	$(STRIP) --strip-debug --strip-unneeded ident2d
	objcopy --add-gnu-debuglink=ident2d.debug ident2d
	$(CC) $(CFLAGS) -shared -fPIC ident2_precache.c -o libident2_precache.so
	objcopy --only-keep-debug libident2_precache.so libident2_precache.so.debug
	$(STRIP) --strip-debug --strip-unneeded libident2_precache.so
	objcopy --add-gnu-debuglink=libident2_precache.so.debug libident2_precache.so

.PHONY: install
install: $(TARGETS)
	install -m 0755 -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGETBINS) $(DESTDIR)$(PREFIX)/bin
	install -m 0755 -d $(DESTDIR)$(PREFIX)/lib/x86_64-linux-gnu
	install -m 0755 $(TARGETLIBS) $(DESTDIR)$(PREFIX)/lib/x86_64-linux-gnu
	install -m 0755 -d $(DESTDIR)/etc/systemd/system
	install -m 0644 ident2d.service $(DESTDIR)/etc/systemd/system
	install -m 0644 ident2d.conf $(DESTDIR)/etc


clean:
	$(RM) -rf ident2d libident2_precache.so libident2_precache.so.debug ident2d.debug debian/ident2d* debian/.debhelper

deb:
	dpkg-buildpackage -b -rfakeroot -us -uc
