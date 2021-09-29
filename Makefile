.SUFFIXES: .in.8 .8

VERSION		 = 1.0.2

HTURI		?= /
WWWDIR		?= /var/www
DATADIR		?= /data
LOGFILE		?= /logs/httpdrop-system.log
CACHEDIR	?= /cache/httpdrop
SECURE		?= -DSECURE

CFLAGS		+= -g -W -Wall -Wextra
CFLAGS_PKG	!= pkg-config --cflags kcgi-html
CFLAGS		+= $(CFLAGS_PKG)
LIBS_PKG	!= pkg-config --libs --static kcgi-html
LIBS		+= $(LIBS_PKG)
DISTDIR		 = /var/www/vhosts/kristaps.bsd.lv/htdocs/httpdrop/snapshots
OBJS		 = auth-file.o main.o
CFLAGS		+= -DHTURI=\"$(HTURI)\"
CFLAGS		+= -DDATADIR=\"$(DATADIR)\"
CFLAGS		+= -DLOGFILE=\"$(LOGFILE)\"
CFLAGS		+= -DCACHEDIR=\"$(CACHEDIR)\"
CFLAGS		+= $(SECURE)
DOTAR		 = Makefile \
		   auth-file.c \
		   bulma.css \
		   errorpage.xml \
		   extern.h \
		   httpdrop.css \
		   httpdrop.in.8 \
		   httpdrop.js \
	   	   loginpage.xml \
		   main.c \
		   page.xml

all: httpdrop httpdrop.8

tgz: httpdrop.tar.gz

httpdrop: $(OBJS)
	$(CC) -static -o $@ $(OBJS) $(LIBS)

$(OBJS): extern.h

install: httpdrop
	mkdir -p $(DESTDIR)$(WWWDIR)/htdocs
	mkdir -p $(DESTDIR)$(WWWDIR)/cgi-bin
	mkdir -p $(DESTDIR)$(WWWDIR)/data
	install -m 0444 httpdrop.css bulma.css httpdrop.js $(DESTDIR)$(WWWDIR)/htdocs
	install -m 0755 httpdrop $(DESTDIR)$(WWWDIR)/cgi-bin
	install -m 0444 errorpage.xml page.xml loginpage.xml $(DESTDIR)$(WWWDIR)/data

installtgz: tgz
	mkdir -p $(DISTDIR)
	install -m 0444 httpdrop.tar.gz $(DISTDIR)/httpdrop-$(VERSION).tar.gz

httpdrop.tar.gz:
	rm -rf .dist
	mkdir -p .dist/httpdrop-$(VERSION)/
	install -m 0644 $(DOTAR) .dist/httpdrop-$(VERSION)
	( cd .dist/ && tar zcf ../$@ ./ )
	rm -rf .dist/

.in.8.8:
	sed -e "s!@DATADIR@!$(WWWDIR)/$(DATADIR)!g" \
		-e "s!@CACHEDIR@!$(WWWDIR)/$(CACHEDIR)!g" \
		-e "s!@LOGFILE@!$(WWWDIR)/$(LOGFILE)!g" $< >$@

clean:
	rm -f httpdrop httpdrop.8 $(OBJS) httpdrop.tar.gz
