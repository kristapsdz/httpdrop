LDFLAGS	+= -L/usr/local/lib
CFLAGS 	+= -I/usr/local/include
CFLAGS	+= -W -Wall -Wextra -g

# URL path (w/trailing slash) of JS/CSS media.
HTURI	 = /

# File-system path (relative to chroot) of XML media.
DATADIR	 = /data/
LOGFILE	 = /logs/httpdrop-system.log
CACHE	 = /cache/httpdrop

sinclude Makefile.local

CFLAGS	+= -DHTURI=\"$(HTURI)\"
CFLAGS	+= -DDATADIR=\"$(DATADIR)\"
CFLAGS	+= -DLOGFILE=\"$(LOGFILE)\"
CFLAGS	+= -DCACHE=\"$(CACHE)\"

httpdrop: main.o
	$(CC) -static -o $@ main.o $(LDFLAGS) -lkcgi -lkcgihtml -lz

installwww: httpdrop
	install -m 0444 httpdrop.css bulma.css httpdrop.js /var/www/htdocs
	install -m 0755 httpdrop /var/www/cgi-bin
	install -m 0444 httpdrop.xml /var/www/data

clean:
	rm -f httpdrop main.o
