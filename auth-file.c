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
 * A user used for logging in and session cookies.
 * This is the data pulled from the htpasswd(1) file.
 */
struct	user {
	char		 *name; /* username */
	char		 *hash; /* bcrypt(3) password */
	TAILQ_ENTRY(user) entries;
};

TAILQ_HEAD(userq, user);

/*
 * Holds all information required for working with the file-based
 * authentication database: htpasswd(1).
 */
struct	auth {
	struct userq	 uq; /* all users */
	int		 enable; /* whether we're doing auth */
};

/*
 * By default, no users, no enable.
 * Returns the auth pointer (never NULL).
 */
void *
auth_file_alloc(void)
{
	struct auth	*p;

	p = kcalloc(1, sizeof(struct auth));
	TAILQ_INIT(&p->uq);
	return(p);
}

/*
 * Free all users allocated during autH_file_init and after
 * auth_file_alloc.
 * Does nothing if "arg" is NULL.
 */
void
auth_file_free(void *arg)
{
	struct auth	*p = arg;
	struct user	*u;

	if (NULL == p)
		return;

	while (NULL != (u = TAILQ_FIRST(&p->uq))) {
		TAILQ_REMOVE(&p->uq, u, entries);
		free(u->name);
		free(u->hash);
		free(u);
	}
	free(p);
}

/*
 * Look up the username, make sure it exists, then check against the
 * given hash using the crypt_checkpass function, which does the heavy
 * lefting for us.
 * Don't report errors: baddies could spam the log.
 * Returns the login token for the user.
 */
int64_t
auth_file_login(const struct sys *sys, void *arg,
	const char *name, const char *pass)
{
	int	 	 fd;
	char		 buf[1024];
	const struct user *u;
	int64_t		 cookie;
	const struct userq *uq = arg;

	TAILQ_FOREACH(u, uq, entries)
		if (0 == strcasecmp(u->name, name))
			break;

	if (NULL == u)
		return(0);
	else if (crypt_checkpass(pass, u->hash))
		return(0);

	/*
	 * Create a random cookie (session token) and overwrite whatever
	 * is currently in our cookie file, if at all.
	 */

	do {
		cookie = arc4random();
	} while (cookie <= 0);

	snprintf(buf, sizeof(buf), "%" PRId64 "\n", cookie);

	fd = openat(sys->authfd, name, 
		O_CREAT | O_RDWR | O_TRUNC, 0600);

	if (-1 == fd) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s", sys->authdir, name);
		return(-1);
	}

	if (write(fd, buf, strlen(buf)) < 0) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s", sys->authdir, name);
		close(fd);
		return(-1);
	}

	close(fd);
	return(cookie);
}

/*
 * Try to open the file ".htpasswd" within the cache directory.
 * Return zero on fatal error, non-zero on success.
 * The "uq" field will not be allocated if the file was not found;
 * otherwise, it will be allocated and filled with a (possibly-zero)
 * user entries.
 * Note that "uq" might be allocated on failure.
 */
int
auth_file_init(const struct sys *sys, void *arg)
{
	int		 fd;
	FILE		*f;
	char		*buf;
	const char	*fn = ".htpasswd";
	size_t		 len, line = 1;
	char		*user, *pass;
	struct user	*u;
	struct auth	*p = arg;

	assert(NULL != p);
	p->enable = 0;

	fd = openat(sys->cachefd, fn, O_RDONLY, 0);

	if (-1 == fd && ENOENT != errno) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s: open", sys->cachedir, fn);
		return(0);
	} else if (-1 == fd) 
		return(1);

	if (-1 == flock(fd, LOCK_SH)) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s: flock", sys->cachedir, fn);
		close(fd);
		return(0);
	}

	p->enable = 1;

	if (NULL == (f = fdopen(fd, "r"))) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s: fopen", sys->cachedir, fn);
		flock(fd, LOCK_UN);
		close(fd);
		return(0);
	}

	while (NULL != (buf = fgetln(f, &len))) {
		if ('\n' != buf[len - 1])
			continue;
		buf[len - 1] = '\0';
		user = buf;
		if (NULL == (pass = strchr(user, ':'))) {
			kutil_warn(&sys->req, NULL, 
				"%s/%s:%zu: bad syntax", 
				sys->cachedir, fn, line);
			fclose(f);
			return(0);
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
	return(1);
}

/*
 * Whether we had an htpasswd(1) file.
 */
int
auth_file_enabled(void *arg)
{
	struct auth	*p = arg;

	return(p->enable);
}

/*
 * Look in the authdir the cookie registered to the current user (who
 * must exist) and cross-check its unique token.
 * Returns zero on failure, non-zero on success.
 */
int
auth_file_check(const struct sys *sys, 
	void *arg, const char *name, int64_t cookie)
{
	int		    nfd, loggedin = 0;
	const struct auth  *p = arg;
	FILE		   *f;
	int64_t		    ccookie;
	const struct user  *u;

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
		return(0);

	if (-1 == (nfd = openat(sys->authfd, name, O_RDONLY, 0))) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s", sys->authdir, name);
		return(0);
	}

	/* Read the cookie token from the file. */

	if (NULL == (f = fdopen(nfd, "r"))) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s", sys->authdir, name);
		close(nfd);
		return(0);
	} else if (1 != fscanf(f, "%" PRId64, &ccookie)) {
		kutil_warnx(&sys->req, NULL, 
			"%s/%s: malformed", sys->authdir, name);
		fclose(f);
		return(0);
	}

	/* Does our cookie token match the one given? */

	if ( ! (loggedin = (cookie == ccookie)))
		kutil_warn(&sys->req, name, "cookie token mismatch");

	fclose(f);
	return(loggedin);
}

void
auth_file_logout(const struct sys *sys, void *arg)
{
	struct auth	*p = arg;

	assert(p->enable);

	if (-1 == unlinkat(sys->authfd, sys->curuser, 0))
		kutil_warn(&sys->req, sys->curuser, 
			"%s/%s", sys->authdir, sys->curuser);
}
