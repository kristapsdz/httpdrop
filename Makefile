CFLAGS		+= -W -Wall -Wextra -g
HTURI		 = /
WWWDIR		 = /var/www
DATADIR		 = /data
LOGFILE		 = /logs/httpdrop-system.log
LOGFFILE	 = /var/www/$(LOGFILE)
CACHEDIR	 = /cache/httpdrop
SECURE		 = -DSECURE
WWWUSER		 = www
VERSION		 = 1.0.0

sinclude Makefile.local

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

httpdrop: $(OBJS)
	$(CC) -static -o $@ $(OBJS) $(LDFLAGS) -lkcgi -lkcgihtml -lzip -lz

tgz: httpdrop.tar.gz

$(OBJS): extern.h

install: httpdrop
	mkdir -p $(WWWDIR)/htdocs
	mkdir -p $(WWWDIR)/cgi-bin
	mkdir -p $(WWWDIR)/data
	touch $(LOGFFILE)
	chown $(WWWUSER) $(LOGFFILE)
	install -m 0444 httpdrop.css bulma.css httpdrop.js $(WWWDIR)/htdocs
	install -m 0755 httpdrop $(WWWDIR)/cgi-bin
	install -m 0444 errorpage.xml page.xml loginpage.xml $(WWWDIR)/data

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
