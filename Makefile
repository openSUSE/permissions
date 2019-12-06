CFLAGS=-W -Wall -g -O2 -std=c11 -Wextra -pedantic -Wduplicated-cond  -Wduplicated-branches  -Wlogical-op  -Wrestrict  -Wnull-dereference  -Wjump-misses-init  -Wdouble-promotion  -Wshadow  -Wformat=2 -Wsign-conversion
# for testing, add sanitizers:
# -fsanitize=address -fsanitize=pointer-compare -fsanitize=pointer-subtract -fsanitize=undefined
CC=gcc
DESTDIR=
LDLIBS=-lcap
prefix=/usr
sysconfdir=/etc
distconfdir=/usr/etc
bindir=$(prefix)/bin
fillupdir=/var/adm/fillup-templates
datadir=$(prefix)/share
mandir=$(datadir)/man
man8dir=$(mandir)/man8
man5dir=$(mandir)/man5
zypp_plugins=$(prefix)/lib/zypp/plugins
zypp_commit_plugins=$(zypp_plugins)/commit

FSCAPS_DEFAULT_ENABLED = 1
CPPFLAGS += -DFSCAPS_DEFAULT_ENABLED=$(FSCAPS_DEFAULT_ENABLED)

all: src/chkstat

install: all
	@for i in $(bindir) $(man8dir) $(man5dir) $(fillupdir) $(sysconfdir) $(distconfdir) $(zypp_commit_plugins); \
		do install -d -m 755 $(DESTDIR)$$i; done
	@install -m 755 src/chkstat $(DESTDIR)$(bindir)
	@install -m 644 man/chkstat.8 $(DESTDIR)$(man8dir)
	@install -m 644 man/permissions.5 $(DESTDIR)$(man5dir)
	@install -m 644 etc/sysconfig.security $(DESTDIR)$(fillupdir)
	@install -m 755 zypper-plugin/permissions.py $(DESTDIR)$(zypp_commit_plugins)
	@for i in etc/permissions profiles/permissions.*; \
		do install -m 644 $$i $(DESTDIR)$(distconfdir); done
	@install -m 644 etc/permissions.local $(DESTDIR)$(sysconfdir)


clean:
	/bin/rm src/chkstat

.PHONY: all clean
