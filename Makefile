CFLAGS=-W -Wall -g -O2
CC=gcc
DESTDIR=
LDLIBS=-lcap
prefix=/usr
sysconfdir=/etc
bindir=$(prefix)/bin
suseconfigdir=/sbin/conf.d
fillupdir=/var/adm/fillup-templates
datadir=$(prefix)/share
mandir=$(datadir)/man
man8dir=$(mandir)/man8

all: chkstat

install: all
	@for i in $(bindir) $(suseconfigdir) $(man8dir) $(fillupdir) $(sysconfdir); \
		do install -d -m 755 $(DESTDIR)$$i; done
	@install -m 755 chkstat $(DESTDIR)$(bindir)
	@install -m 755 SuSEconfig.permissions $(DESTDIR)$(suseconfigdir)
	@install -m 644 chkstat.8 $(DESTDIR)$(man8dir)
	@install -m 644 sysconfig.security $(DESTDIR)$(fillupdir)
	@for i in permissions{,.local,.easy,.secure,.paranoid}; \
		do install -m 644 $$i $(DESTDIR)$(sysconfdir); done


clean:
	/bin/rm chkstat

.PHONY: all clean
