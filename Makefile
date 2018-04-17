CFLAGS		+= -W -Wall -Wextra -g
HTURI		 = /
WWWDIR		 = /var/www
DATADIR		 = /data
LOGFILE		 = /logs/httpdrop-system.log
LOGFFILE	 = /var/www/$(LOGFILE)
CACHEDIR	 = /cache/httpdrop
SECURE		 = -DSECURE

sinclude Makefile.local

OBJS		 = auth-file.o main.o
CFLAGS		+= -DHTURI=\"$(HTURI)\"
CFLAGS		+= -DDATADIR=\"$(DATADIR)\"
CFLAGS		+= -DLOGFILE=\"$(LOGFILE)\"
CFLAGS		+= -DCACHEDIR=\"$(CACHEDIR)\"
CFLAGS		+= $(SECURE)

httpdrop: $(OBJS)
	$(CC) -static -o $@ $(OBJS) $(LDFLAGS) -lkcgi -lkcgihtml -lzip -lz

$(OBJS): extern.h

installwww: httpdrop
	mkdir -p $(WWWDIR)/htdocs
	mkdir -p $(WWWDIR)/cgi-bin
	mkdir -p $(WWWDIR)/data
	touch $(LOGFFILE)
	chown www $(LOGFFILE)
	install -m 0444 httpdrop.css bulma.css httpdrop.js $(WWWDIR)/htdocs
	install -m 0755 httpdrop $(WWWDIR)/cgi-bin
	install -m 0444 errorpage.xml page.xml loginpage.xml $(WWWDIR)/data

clean:
	rm -f httpdrop $(OBJS)
