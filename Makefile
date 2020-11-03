CXXFLAGS=-g -O2 -std=c++17 -Werror -Wall -Wextra -pedantic -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wnull-dereference -Wdouble-promotion  -Wshadow  -Wformat=2 -Wsign-conversion
ifdef CHKSTAT_TEST
# for testing, add sanitizers:
CXXFLAGS+=-fsanitize=address -fsanitize=pointer-compare -fsanitize=pointer-subtract -fsanitize=undefined
endif
# if debugging is desired then remove optimizations
ifdef CHKSTAT_DEBUG
CXXFLAGS+=-O0
endif
CXX=g++
# link statically against libstdc++. since some people are afraid of ABI
# changes in this area and since permissions is a base package in SUSE this
# protects us from such potential breakage at the expense of some increased
# binary size
LDFLAGS=-static-libstdc++ -Wl,--as-needed
DESTDIR=
LDLIBS=-lcap
prefix=/usr
sysconfdir=/etc
permissionsdir=/usr/share/permissions
bindir=$(prefix)/bin
fillupdir=/var/adm/fillup-templates
datadir=$(prefix)/share
mandir=$(datadir)/man
man8dir=$(mandir)/man8
man5dir=$(mandir)/man5
zypp_plugins=$(prefix)/lib/zypp/plugins
zypp_commit_plugins=$(zypp_plugins)/commit

OBJS = src/chkstat.o src/utility.o src/formatting.o

all: src/chkstat
	@if grep -n -o -P '\t' src/*.cpp src/*.h; then echo "error: source has mixed tabs and spaces!" ; touch src/chkstat.cpp ; exit 1 ; fi ; :

install: all
	@for i in $(bindir) $(man8dir) $(man5dir) $(fillupdir) $(sysconfdir) $(permissionsdir) $(zypp_commit_plugins); \
		do install -d -m 755 $(DESTDIR)$$i; done
	@install -m 755 src/chkstat $(DESTDIR)$(bindir)
	@install -m 644 man/chkstat.8 $(DESTDIR)$(man8dir)
	@install -m 644 man/permissions.5 $(DESTDIR)$(man5dir)
	@install -m 644 etc/sysconfig.security $(DESTDIR)$(fillupdir)
	@install -m 755 zypper-plugin/permissions.py $(DESTDIR)$(zypp_commit_plugins)
	@for i in etc/variables.conf etc/permissions profiles/permissions.*; \
		do install -m 644 $$i $(DESTDIR)$(permissionsdir); done
	@install -m 644 etc/permissions.local $(DESTDIR)$(sysconfdir)

%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

src/chkstat.o: src/*.h
src/utility.o: src/utility.h

src/chkstat: $(OBJS) | /usr/include/tclap
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -osrc/chkstat src/*.o $(LDLIBS)

/usr/include/tclap:
	@echo "error: The tclap command line parsing library is required for building. Try 'zypper in tclap'."; exit 1; :

clean:
	/bin/rm -f src/chkstat src/*.o

.PHONY: all clean
