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
man5dir=$(mandir)/man5
zypp_plugins=$(prefix)/lib/zypp/plugins
zypp_commit_plugins=$(zypp_plugins)/commit

FSCAPS_DEFAULT_ENABLED = 1
CPPFLAGS += -DFSCAPS_DEFAULT_ENABLED=$(FSCAPS_DEFAULT_ENABLED)

all: chkstat

install: all
	@for i in $(bindir) $(suseconfigdir) $(man8dir) $(man5dir) $(fillupdir) $(sysconfdir) $(zypp_commit_plugins); \
		do install -d -m 755 $(DESTDIR)$$i; done
	@install -m 755 chkstat $(DESTDIR)$(bindir)
	@install -m 644 chkstat.8 $(DESTDIR)$(man8dir)
	@install -m 644 permissions.5 $(DESTDIR)$(man5dir)
	@install -m 644 sysconfig.security $(DESTDIR)$(fillupdir)
	@install -m 755 zypper-plugin/permissions.py $(DESTDIR)$(zypp_commit_plugins)
	@for i in permissions{,.local,.easy,.secure,.paranoid}; \
		do install -m 644 $$i $(DESTDIR)$(sysconfdir); done


clean:
	/bin/rm chkstat

package:
	@obs/mkpackage

.PHONY: all clean package
