CFLAGS		+= -W -Wall -Wextra -g
HTURI		?= /
WWWDIR		?= /var/www
DATADIR		?= /data
LOGFILE		?= /logs/httpdrop-system.log
CACHEDIR	?= /cache/httpdrop
SECURE		?= -DSECURE

VERSION		 = 1.0.0
DISTDIR		 = /var/www/vhosts/capem.io/htdocs/dists
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
		   httpdrop.js \
	   	   loginpage.xml \
		   main.c \
		   page.xml

all: httpdrop

tgz: httpdrop.tar.gz

httpdrop: $(OBJS)
	$(CC) -static -o $@ $(OBJS) $(LDFLAGS) -lkcgi -lkcgihtml -lz

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
	mkdir -p .dist/httpdrop-$(VERSION)/
	install -m 0644 $(DOTAR) .dist/httpdrop-$(VERSION)
	( cd .dist/ && tar zcf ../$@ ./ )
	rm -rf .dist/

clean:
	rm -f httpdrop $(OBJS) httpdrop.tar.gz
