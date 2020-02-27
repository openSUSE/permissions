CFLAGS=-W -Wall -g -O2
CC=gcc
DESTDIR=
LDLIBS=
prefix=/usr
sysconfdir=/etc
bindir=$(prefix)/bin
suseconfigdir=/sbin/conf.d
fillupdir=/var/adm/fillup-templates
datadir=$(prefix)/share
mandir=$(datadir)/man
man8dir=$(mandir)/man8
man5dir=$(mandir)/man5

all: chkstat

install: all
	@for i in $(bindir) $(suseconfigdir) $(man8dir) $(man5dir) $(fillupdir) $(sysconfdir); \
		do install -d -m 755 $(DESTDIR)$$i; done
	@install -m 755 SuSEconfig.permissions $(DESTDIR)$(suseconfigdir)
	@install -m 755 chkstat $(DESTDIR)$(bindir)
	@install -m 644 chkstat.8 $(DESTDIR)$(man8dir)
	@install -m 644 sysconfig.security $(DESTDIR)$(fillupdir)
	@for i in permissions{,.local,.easy,.secure,.paranoid}; \
		do install -m 644 $$i $(DESTDIR)$(sysconfdir); done


clean:
	/bin/rm -f chkstat

package:
	@obs/mkpackage

.PHONY: all clean package install
