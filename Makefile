LDFLAGS	+= -L/usr/local/lib
CFLAGS 	+= -I/usr/local/include
CFLAGS	+= -W -Wall -Wextra -g

HTURI	 = /
WWWDIR	 = /var/www
DATADIR	 = /data
LOGFILE	 = /logs/httpdrop-system.log
CACHEDIR = /cache/httpdrop
SECURE	 = -DSECURE

sinclude Makefile.local

CFLAGS	+= -DHTURI=\"$(HTURI)\"
CFLAGS	+= -DDATADIR=\"$(DATADIR)\"
CFLAGS	+= -DLOGFILE=\"$(LOGFILE)\"
CFLAGS	+= -DCACHE=\"$(CACHEDIR)\"
CFLAGS	+= $(SECURE)

httpdrop: main.o
	$(CC) -static -o $@ main.o $(LDFLAGS) -lkcgi -lkcgihtml -lz

installwww: httpdrop
	mkdir -p $(WWWDIR)/htdocs
	mkdir -p $(WWWDIR)/cgi-bin
	mkdir -p $(WWWDIR)/data
	install -m 0444 httpdrop.css bulma.css httpdrop.js $(WWWDIR)/htdocs
	install -m 0755 httpdrop $(WWWDIR)/cgi-bin
	install -m 0444 errorpage.xml page.xml loginpage.xml $(WWWDIR)/data

clean:
	rm -f httpdrop main.o
