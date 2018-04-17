/*	$Id$ */
#include <sys/queue.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <kcgi.h>

#include "extern.h"

/*
 * Free all users allocated during auth_file_init.
 * Does nothing if "arg" is NULL.
 */
void
auth_file_free(struct auth *p)
{
	struct user	*u;

	if (NULL == p)
		return;

	while (NULL != (u = TAILQ_FIRST(&p->uq))) {
		TAILQ_REMOVE(&p->uq, u, entries);
		free(u->name);
		free(u->hash);
		free(u);
	}
}

/*
 * Look up the username, make sure it exists, then check against the
 * given hash using the crypt_checkpass function, which does the heavy
 * lefting for us.
 * Don't report errors: baddies could spam the log.
 * Returns the login token for the user, zero if the user was not found,
 * or -1 if system errors occur.
 */
int64_t
auth_file_login(const struct sys *sys, const struct auth *p,
	const char *name, const char *pass)
{
	int	 	 fd, len;
	char		 buf[32];
	char		*nbuf;
	const struct user *u;
	int64_t		 cookie;

	TAILQ_FOREACH(u, &p->uq, entries)
		if (0 == strcasecmp(u->name, name))
			break;

	if (NULL == u)
		return 0;
	else if (crypt_checkpass(pass, u->hash))
		return 0;

	/*
	 * Create a random cookie (session token) and overwrite whatever
	 * is currently in our cookie file, if at all.
	 */
again:
	do {
		cookie = arc4random();
	} while (cookie <= 0);

	snprintf(buf, sizeof(buf), "%" PRId64, cookie);

	fd = openat(sys->authfd, buf, 
		O_CREAT | O_RDWR | O_EXCL, 0600);

	if (-1 == fd) {
		if (EEXIST == errno)
			goto again;
		kutil_warn(&sys->req, name, AUTHDIR "/%s", buf);
		return -1;
	}

	len = kasprintf(&nbuf, "%s\n", name);
	if (write(fd, nbuf, len) < 0) {
		kutil_warn(&sys->req, name, AUTHDIR "/%s", buf);
		close(fd);
		return -1;
	}

	close(fd);
	free(nbuf);
	return cookie;
}

int
auth_file_chpass(const struct sys *sys, 
	const char *oldpass, const char *newpass)
{
	int		 fd, rc = 0;
	FILE		*f;
	char		*buf;
	size_t		 len, line = 1;
	char		*user, *pass;
	struct user	*u;
	struct userq	 uq;

	/* Open and exclusive-lock the password file. */

	fd = open(CACHEDIR "/.htpasswd", O_RDWR, 0);
	if (-1 == fd) {
		kutil_warn(&sys->req, sys->curuser, 
			CACHEDIR "/.htpasswd");
		return 0;
	} else if (-1 == flock(fd, LOCK_EX)) {
		kutil_warn(&sys->req, sys->curuser, 
			CACHEDIR "/.htpasswd");
		close(fd);
		return 0;
	} else if (NULL == (f = fdopen(fd, "r+"))) {
		kutil_warn(&sys->req, sys->curuser, 
			CACHEDIR "/.htpasswd");
		flock(fd, LOCK_UN);
		close(fd);
		return 0;
	}

	/* 
	 * Copy out all users. 
	 * From here on our, use the "out" label, which will clean up
	 * the user/password array.
	 */

	TAILQ_INIT(&uq);
	while (NULL != (buf = fgetln(f, &len))) {
		if ('\n' != buf[len - 1])
			continue;
		buf[len - 1] = '\0';
		user = buf;
		if (NULL == (pass = strchr(user, ':'))) {
			kutil_warnx(&sys->req, sys->curuser, 
				CACHEDIR "/.htpasswd:%zu: "
				"bad syntax", line);
			goto out;
		}
		(*pass++) = '\0';
		u = kcalloc(1, sizeof(struct user));
		u->name = kstrdup(user);
		u->hash = kstrdup(pass);
		TAILQ_INSERT_TAIL(&uq, u, entries);
		line++;
	}

	/* 
	 * Check if we have the requested user. 
	 * Make sure that their password is good.
	 */

	TAILQ_FOREACH(u, &uq, entries)
		if (0 == strcasecmp(u->name, sys->curuser))
			break;

	if (NULL == u) {
		kutil_warnx(&sys->req, sys->curuser, CACHEDIR 
			"/.htpasswd: user disappeared");
		goto out;
	} else if (crypt_checkpass(oldpass, u->hash)) {
		kutil_warnx(&sys->req, sys->curuser, CACHEDIR 
			"/.htpasswd: bad old password: %s", oldpass);
		goto out;
	}

	/* Hash the new password in its place. */

	free(u->hash);
	u->hash = malloc(128 + 1);
	u->hash[128] = '\0';

	if (crypt_newhash(newpass, 
   	    "bcrypt,a", u->hash, 128)) {
		kutil_warn(&sys->req, sys->curuser, "crypt_newhash");
		goto out;
	}

	/* Now re-serialise the list. */

	rewind(f);
	TAILQ_FOREACH(u, &uq, entries) {
		if (fprintf(f, "%s:%s\n", u->name, u->hash) > 0) 
			continue;
		kutil_warn(&sys->req, sys->curuser, 
			CACHEDIR "/.htpasswd");
		goto out;
	}

	rc = 1;
out:
	flock(fd, LOCK_UN);
	fclose(f);
	while (NULL != (u = TAILQ_FIRST(&uq))) {
		TAILQ_REMOVE(&uq, u, entries);
		free(u->name);
		free(u->hash);
		free(u);
	}
	return rc;
}

/*
 * Open our authorisation file and reads in all authorised principles.
 * If the file does not exist, then this will indicate that there is no
 * authorisation enabled for this system.
 * If the file exists---even if it fails parsing or has no
 * principles---then authorisation is assumed to exist.
 * Return zero on failure, non-zero on success.
 */
int
auth_file_init(const struct sys *sys, struct auth *p)
{
	int		 fd;
	FILE		*f;
	char		*buf;
	size_t		 len, line = 1;
	char		*user, *pass;
	struct user	*u;

	assert(NULL != p);
	p->enable = 0;

	fd = open(CACHEDIR "/.htpasswd", O_RDONLY, 0);

	if (-1 == fd && ENOENT != errno) {
		kutil_warn(&sys->req, NULL, 
			CACHEDIR "/.htpasswd");
		return 0;
	} else if (-1 == fd) 
		return 1;

	/* 
	 * Since we were able to open the file, we have authorisation
	 * enabled---even if there are no entries.
	 */

	p->enable = 1;

	if (-1 == flock(fd, LOCK_EX)) {
		kutil_warn(&sys->req, NULL, 
			CACHEDIR "/.htpasswd");
		close(fd);
		return 0;
	}

	if (NULL == (f = fdopen(fd, "r"))) {
		kutil_warn(&sys->req, NULL, 
			CACHEDIR "/.htpasswd");
		flock(fd, LOCK_UN);
		close(fd);
		return 0;
	}

	while (NULL != (buf = fgetln(f, &len))) {
		if ('\n' != buf[len - 1])
			continue;
		buf[len - 1] = '\0';
		user = buf;
		if (NULL == (pass = strchr(user, ':'))) {
			kutil_warn(&sys->req, NULL, 
				CACHEDIR "/.htpasswd:%zu: "
				"bad syntax", line);
			flock(fd, LOCK_UN);
			fclose(f);
			return 0;
		}
		(*pass++) = '\0';
		u = kcalloc(1, sizeof(struct user));
		u->name = kstrdup(user);
		u->hash = kstrdup(pass);
		TAILQ_INSERT_TAIL(&p->uq, u, entries);
		line++;
	}

	flock(fd, LOCK_UN);
	fclose(f); 
	return 1;
}

/*
 * Look in the authdir the cookie registered to the current user (who
 * must exist) and cross-check its unique token.
 * Returns zero on failure, non-zero on success.
 */
int
auth_file_check(const struct sys *sys, 
	const struct auth *p, const char *name, int64_t cookie)
{
	int		    nfd, loggedin = 0;
	FILE		   *f;
	const struct user  *u;
	char		    buf[32];
	char		   *line = NULL;
	size_t		    linesz = 0;
	ssize_t		    linelen;

	assert(p->enable);

	/* 
	 * Loop for user in known users.
	 * If we don't find one, just exit.
	 * This prevents an attacker from spamming the log.
	 */

	TAILQ_FOREACH(u, &p->uq, entries)
		if (0 == strcasecmp(u->name, name))
			break;

	if (NULL == u)
		return 0;

	snprintf(buf, sizeof(buf), "%" PRId64, cookie);

	if (-1 == (nfd = openat(sys->authfd, buf, O_RDONLY, 0))) {
		if (ENOENT != errno)
			kutil_warn(&sys->req, name, 
				AUTHDIR "/%s", buf);
		else
			kutil_info(&sys->req, name, 
				AUTHDIR "/%s: cookie not found", buf);
		return 0;
	}

	/* Read the username from the file. */

	if (NULL == (f = fdopen(nfd, "r"))) {
		kutil_warn(&sys->req, name, AUTHDIR "/%s", buf);
		close(nfd);
		return 0;
	}

	if (-1 == (linelen = getline(&line, &linesz, f))) {
		kutil_warn(&sys->req, name, AUTHDIR "/%s", buf);
		fclose(f);
		return 0;
	}

	assert(linelen > 0);
	assert('\n' == line[linelen - 1]);
	line[linelen - 1] = '\0';

	/* Does our cookie token match the one given? */

	if ( ! (loggedin = (0 == strcmp(line, name))))
		kutil_info(&sys->req, name, 
			"cookie owner mismatch: have %s", line);

	free(line);
	fclose(f);
	return loggedin;
}

void
auth_file_logout(const struct sys *sys, struct auth *p)
{
	char	 buf[32];

	assert(p->enable);

	snprintf(buf, sizeof(buf), "%" PRId64, sys->curcookie);
	if (-1 != unlinkat(sys->authfd, buf, 0))
		return;
	kutil_warn(&sys->req, sys->curuser, AUTHDIR "/%s", buf);
}
