/*	$Id$ */
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
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
#include <kcgihtml.h>

#ifndef	CACHEDIR
# define CACHEDIR "/cache/httpdrop"
#endif
#ifndef	FILEDIR
# define FILEDIR "files"
#endif
#ifndef	AUTHDIR
# define AUTHDIR "cookies"
#endif

enum	page {
	PAGE_INDEX,
	PAGE__MAX
};

enum	action {
	ACTION_GET,
	ACTION_LOGIN,
	ACTION_LOGOUT,
	ACTION_MKDIR,
	ACTION_MKFILE,
	ACTION_RMDIR,
	ACTION_RMFILE,
	ACTION__MAX
};

enum	key {
	KEY_DIR,
	KEY_FILE,
	KEY_FILENAME,
	KEY_OP,
	KEY_PASSWD,
	KEY_SESSCOOKIE,
	KEY_SESSUSER,
	KEY_USER,
	KEY__MAX
};

enum	ftype {
	FTYPE_DIR, /* directory */
	FTYPE_FILE, /* regular file */
	FTYPE_OTHER
};

enum	loginerr {
	LOGINERR_NOFIELD, /* HTML field not filled in */
	LOGINERR_BADCREDS, /* bad username/password */
	LOGINERR_SYSERR, /* system error */
	LOGINERR_OK
};

/*
 * A file reference used for listing directory contents.
 */
struct	fref {
	char		*name; /* name of file in path */
	char		*fullname; /* fullname of file */
	struct stat	 st; /* last known stat */
};

/*
 * A user used for logging in and session cookies.
 */
struct	user {
	char		*name; /* username */
	char		*hash; /* bcrypt(3) password */
	TAILQ_ENTRY(user) entries;
};

TAILQ_HEAD(userq, user);

/*
 * Used for login page template.
 */
struct	loginpage {
	enum loginerr	 error; /* login page error */
	struct kreq	*req; /* HTTP request */
};

/*
 * Used for regular directory page listing template.
 */
struct	dirpage {
	struct fref	*frefs; /* file references */
	size_t		 frefsz; /* all file count */
	size_t		 rfilesz; /* regular file count */
	int		 rdwr; /* is read-writable? */
	int		 root; /* is document root? */
	int		 loggedin; /* is logged in? */
	const char	*fpath; /* request path w/script name */
	struct kreq	*req; /* HTTP request */
};

/*
 * Used for error page template.
 */
struct	errorpage {
	const char	*msg; /* error message */
	int		 loggedin; /* is logged in? */
	struct kreq	*req; /* HTTP request */
};

static const char *const pages[PAGE__MAX] = {
	"index", /* PAGE_INDEX */
};

static const struct kvalid keys[KEY__MAX] = {
	{ kvalid_stringne, "dir" }, /* KEY_DIR */
	{ NULL, "file" }, /* KEY_FILE */
	{ kvalid_stringne, "filename" }, /* KEY_FILENAME */
	{ kvalid_stringne, "op" }, /* KEY_OP */
	{ kvalid_stringne, "passwd" }, /* KEY_PASSWD */
	{ kvalid_int, "stok" }, /* KEY_SESSCOOKIE */
	{ kvalid_stringne, "suser" }, /* KEY_SESSUSER */
	{ kvalid_stringne, "user" }, /* KEY_USER */
};

static void
errorpage(struct kreq *, const char *, ...) 
	__attribute__((format(printf, 2, 3)));

/*
 * Fill out all HTTP secure headers.
 * Use the existing document's MIME type.
 * Then emit the body indicator.
 */
static void
http_open(struct kreq *r, enum khttp code)
{

	khttp_head(r, kresps[KRESP_STATUS], 
		"%s", khttps[code]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE], 
		"%s", kmimetypes[r->mime]);
	khttp_head(r, "X-Content-Type-Options", "nosniff");
	khttp_head(r, "X-Frame-Options", "DENY");
	khttp_head(r, "X-XSS-Protection", "1; mode=block");
	khttp_body(r);
}

static int
loginpage_template(size_t index, void *arg)
{
	struct loginpage *l = arg;

	switch (index) {
	case 0:
		khttp_puts(l->req, l->req->fullpath);
		break;
	case 1:
		switch (l->error) {
		case LOGINERR_BADCREDS:
			khttp_puts(l->req, "error-badcreds");
			break;
		case LOGINERR_NOFIELD:
			khttp_puts(l->req, "error-nofield");
			break;
		case LOGINERR_SYSERR:
			khttp_puts(l->req, "error-syserr");
			break;
		default:
			break;
		}
		break;
	default:
		return(0);
	}

	return(1);
}

static void
loginpage(struct kreq *r, enum loginerr error)
{
	struct ktemplate t;
	struct loginpage l;
	const char *const ts[] = { "URL", "CLASS" };

	l.req = r;
	l.error = error;

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = ts;
	t.keysz = 2;
	t.arg = &l;
	t.cb = loginpage_template;
	http_open(r, KHTTP_200);
	khttp_template(r, &t, DATADIR "/loginpage.xml");
}

static int
errorpage_template(size_t index, void *arg)
{
	struct errorpage *pg = arg;
	struct khtmlreq	  req;

	khtml_open(&req, pg->req, KHTML_PRETTY);

	switch (index) {
	case 0:
		khtml_puts(&req, pg->req->fullpath);
		break;
	case 1:
		break;
	case 2:
		khtml_puts(&req, pg->msg);
		break;
	default:
		khtml_close(&req);
		return(0);
	}

	khtml_close(&req);
	return(1);
}

static void
errorpage(struct kreq *r, const char *fmt, ...)
{
	struct errorpage pg;
	char		*buf;
	va_list		 ap;
	struct ktemplate t;
	const char *const ts[] = { "URL", "CLASSES", "MESSAGE" };

	va_start(ap, fmt);
	if (-1 == vasprintf(&buf, fmt, ap))
		exit(EXIT_FAILURE);
	va_end(ap);

	pg.msg = buf;
	pg.req = r;

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = ts;
	t.keysz = 3;
	t.arg = &pg;
	t.cb = errorpage_template;
	http_open(r, KHTTP_200);
	khttp_template(r, &t, DATADIR "/errorpage.xml");
	free(buf);
}

/*
 * Sort the files first by type (directory first, then files), then by
 * name.
 * Used with qsort().
 */
static int
fref_cmp(const void *p1, const void *p2)
{
	const struct fref *f1 = p1, *f2 = p2;

	if (S_ISDIR(f1->st.st_mode) && ! S_ISDIR(f2->st.st_mode))
		return(-1);
	if (S_ISDIR(f2->st.st_mode) && ! S_ISDIR(f1->st.st_mode))
		return(1);

	return(strcmp(f1->name, f2->name));
}

/*
 * See if the current user can access the "st" resource.
 * This checks all possible permissions EXCEPT for suid and friends.
 * It assumes that the user is not root.
 * (Otherwise the permission check is useless.)
 */
static int
check_canwrite(const struct stat *st)
{
	int		 isw = 0, i, groupsz;
	gid_t		 groups[NGROUPS_MAX];

	if ((S_IWOTH & st->st_mode) ||
	    (st->st_uid == getuid() && (S_IWUSR & st->st_mode)) ||
	    (st->st_gid == getgid() && (S_IWGRP & st->st_mode))) {
		isw = 1;
	} else if (S_IWGRP & st->st_mode) {
		groupsz = getgroups(sizeof(groups), groups);
		if (-1 == groupsz)
			return(-1);
		for (i = 0; i < groupsz; i++) {
			if (st->st_gid == groups[i])
				break;
		}
		isw = i < groupsz;
	}
	return(isw);
}

static int
get_dir_template(size_t index, void *arg)
{
	struct dirpage	*pg = arg;
	struct khtmlreq	 req;
	struct fref	*ff;
	size_t		 i;
	char		 classes[1024];

	khtml_open(&req, pg->req, KHTML_PRETTY);

	if (0 == index) {
		khtml_puts(&req, pg->req->fullpath);
		khtml_close(&req);
		return(1);
	} else if (1 == index) {
		classes[0] = '\0';
		strlcat(classes, pg->rdwr ?
			" mutable" : " immutable", sizeof(classes));
		strlcat(classes, pg->root ?
			" root" : " nonroot", sizeof(classes));
		strlcat(classes, pg->rfilesz > 0 ?
			" nonempty" : " empty", sizeof(classes));
		strlcat(classes, pg->loggedin ?
			" loggedin" : "", sizeof(classes));
		khttp_puts(pg->req, classes);
		khtml_close(&req);
		return(1);
	} else if (2 == index) {
		if (NULL != pg->req->cookiemap[KEY_SESSUSER])
			khtml_puts(&req, pg->req->cookiemap[KEY_SESSUSER]->parsed.s);
		khtml_close(&req);
		return(1);
	} else if (index > 3) {
		khtml_close(&req);
		return(0);
	}

	if (pg->frefsz)
		khtml_elem(&req, KELEM_UL);

	for (i = 0; i < pg->frefsz; i++) {
		ff = &pg->frefs[i];
		khtml_elem(&req, KELEM_LI);
		khtml_attr(&req, KELEM_A,
			KATTR_HREF, ff->fullname, 
			KATTR__MAX);
		khtml_puts(&req, ff->name);
		if (S_ISDIR(ff->st.st_mode))
			khtml_puts(&req, "/");
		khtml_closeelem(&req, 1);

		khtml_elem(&req, KELEM_SPAN);
		if (S_ISDIR(ff->st.st_mode)) {
			khtml_puts(&req, "");
		} else if (ff->st.st_size > 1024 * 1024 * 1024) {
			khtml_int(&req, 
				ff->st.st_size / 1024/1024/1024);
			khtml_puts(&req, " GB");
		} else if (ff->st.st_size > 1024 * 1024) {
			khtml_int(&req, 
				ff->st.st_size / 1024/1024);
			khtml_puts(&req, " MB");
		} else if (ff->st.st_size > 1024) {
			khtml_int(&req, ff->st.st_size / 1024);
			khtml_puts(&req, " KB");
		} else {
			khtml_int(&req, ff->st.st_size);
			khtml_puts(&req, " B");
		}
		khtml_closeelem(&req, 1);

		khtml_elem(&req, KELEM_SPAN);
		khtml_puts(&req, ctime(&ff->st.st_ctim.tv_sec));
		khtml_closeelem(&req, 1);

		if (pg->rdwr && ! (S_ISDIR(ff->st.st_mode))) {
			khtml_attr(&req, KELEM_FORM,
				KATTR_METHOD, "post",
				KATTR_CLASS, "icon",
				KATTR_ACTION, pg->fpath,
				KATTR__MAX);
			khtml_attr(&req, KELEM_INPUT,
				KATTR_TYPE, "hidden",
				KATTR_NAME, keys[KEY_OP].name,
				KATTR_VALUE, "rmfile",
				KATTR__MAX);
			khtml_attr(&req, KELEM_INPUT,
				KATTR_TYPE, "hidden",
				KATTR_NAME, keys[KEY_FILENAME].name,
				KATTR_VALUE, ff->name,
				KATTR__MAX);
			khtml_attr(&req, KELEM_DIV,
				KATTR_CLASS, "field is-small",
				KATTR__MAX);

			/*
			 * Disallow deletion if we don't have access
			 * rights to the file.
			 */

			if (check_canwrite(&ff->st) > 0)
				khtml_attr(&req, KELEM_BUTTON,
					KATTR_CLASS, "button "
						"is-danger is-outlined",
					KATTR_TITLE, "Delete",
					KATTR_TYPE, "submit",
					KATTR__MAX);
			else
				khtml_attr(&req, KELEM_BUTTON,
					KATTR_CLASS, "button "
						"is-danger is-outlined",
					KATTR_TITLE, "Delete",
					KATTR_DISABLED, "disabled",
					KATTR_TYPE, "submit",
					KATTR__MAX);
			khtml_attr(&req, KELEM_SPAN,
				KATTR_CLASS, "icon is-small",
				KATTR__MAX);
			khtml_attr(&req, KELEM_I,
				KATTR_CLASS, "fa fa-times",
				KATTR__MAX);
			khtml_closeelem(&req, 5);
		}

		khtml_closeelem(&req, 1);
	}

	/* XXX: use CSS ids/subclassing and keep in XML. */

	if (0 == pg->frefsz) {
		khtml_elem(&req, KELEM_P);
		khtml_puts(&req, 
			"No files or directories to list. "
			"Time to create or upload some?");
		khtml_closeelem(&req, 1);
	} else {
		khtml_closeelem(&req, 1);
	}

	khtml_closeelem(&req, 4);
	khtml_close(&req);
	return(1);
}

/*
 * Print a directory listing.
 * This is preceded by the form for directory creation and file upload.
 * FIXME: use directory mtime and cache control.
 */
static void
get_dir(int fd, const char *path, int rdwr, struct kreq *r, int login)
{
	int		 nfd;
	struct stat	 st;
	char		*fpath;
	DIR		*dir;
	struct dirent	*dp;
	int		 fl = O_RDONLY | O_DIRECTORY;
	size_t		 filesz = 0, rfilesz = 0, i;
	struct ktemplate t;
	const char *const ts[] = { "URL", "CLASSES", "USER", "FILES" };
	struct fref	*files = NULL;
	struct dirpage	 dirpage;

	if ('\0' != path[0]) {
		if (-1 == (nfd = openat(fd, path, fl, 0)))
			kutil_warn(r, NULL, "%s: openat", path);
	} else if (-1 == (nfd = dup(fd)))
		kutil_warn(r, NULL, "%s: dup", path);

	if (-1 == nfd) {
		errorpage(r, "Cannot open directory \"%s\".", path);
		return;
	}

	/* 
	 * Get the DIR pointer from the directory request.
	 * Then read all acceptable entries into our "files" array.
	 */

	if (NULL == (dir = fdopendir(nfd))) {
		kutil_warn(r, NULL, "%s: fdopendir", path);
		errorpage(r, "Cannot scan directory \"%s\".", path);
		return;
	}

	while (NULL != (dp = readdir(dir))) {
		/* 
		 * Disallow non-regular or directory, the current
		 * directory, and previous when in the root.
		 * Also don't let fstat errors flow.
		 */

		if ((DT_DIR != dp->d_type && 
		     DT_REG != dp->d_type) ||
		    0 == strcmp(dp->d_name, "."))
			continue;
		if (0 == strcmp(dp->d_name, "..") &&
		    '\0' == path[0])
			continue;
		if (-1 == fstatat(nfd, dp->d_name, &st, 0))
			continue;

		/* Get file information... */

		kasprintf(&fpath, "%s/%s%s%s", r->pname, 
			path, '\0' != path[0] ? "/" : "", dp->d_name);
		files = kreallocarray(files, 
			filesz + 1, sizeof(struct fref));
		files[filesz].st = st;
		files[filesz].name = kstrdup(dp->d_name);
		files[filesz].fullname = fpath;
		filesz++;
		if (strcmp(dp->d_name, ".."))
			rfilesz++;
	}

	closedir(dir);

	qsort(files, filesz, sizeof(struct fref), fref_cmp);

	kasprintf(&fpath, "%s/%s%s", r->pname, 
		path, '\0' != path[0] ? "/" : "");

	dirpage.frefs = files;
	dirpage.frefsz = filesz;
	dirpage.rfilesz = rfilesz;
	dirpage.rdwr = rdwr;
	dirpage.fpath = fpath;
	dirpage.req = r;
	dirpage.loggedin = login;
	dirpage.root = '\0' == path[0];

	/*
	 * No more errors reported.
	 * Print all of our entities along with a header allowing us to
	 * upload more files.
	 */

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = ts;
	t.keysz = 4;
	t.arg = &dirpage;
	t.cb = get_dir_template;

	http_open(r, KHTTP_200);
	khttp_template(r, &t, DATADIR "/page.xml");

	free(fpath);
	for (i = 0; i < filesz; i++) {
		free(files[i].name);
		free(files[i].fullname);
	}
	free(files);
}

/*
 * Grok a file.
 * All we do use is the template feature to print out.
 */
static void
get_file(int fd, const char *path, struct kreq *r)
{
	int		  nfd;

	nfd = openat(fd, path, O_RDONLY, 0);
	if (-1 == nfd) {
		kutil_warn(r, NULL, "%s: openat", path);
		errorpage(r, "Cannot open file \"%s\".", path);
		return;
	}

	/*
	 * FIXME: use last-updated with the struct state of the
	 * file and cross-check.
	 */

	http_open(r, KHTTP_200);
	khttp_template_fd(r, NULL, nfd, path);
	close(nfd);
}

/*
 * Send a 301 error back to the current page.
 * This is used after making a POST.
 */
static void
send_301_path(struct kreq *r, const char *fullpath)
{
	char	*np, *path;

	kasprintf(&path, "%s%s%s", r->pname, 
		'/' != fullpath[0] ? "/" : "", fullpath);
	np = kutil_urlabs(r->scheme, r->host, r->port, path);
	free(path);

	khttp_head(r, kresps[KRESP_LOCATION], "%s", np);
	http_open(r, KHTTP_303);
	khttp_puts(r, "Redirecting...");
	free(np);
}

/*
 * Send a 301 error back to the current page.
 * This is used after making a POST.
 */
static void
send_301(struct kreq *r)
{

	send_301_path(r, r->fullpath);
}

/*
 * Unlink a regular file "fn" relative to the current path "path" with
 * file descriptor "nfd".
 */
static void
post_op_rmfile(int nfd, const char *path,
	const char *fn, struct kreq *r)
{

	if (-1 == unlinkat(nfd, fn, 0) && ENOENT != errno) {
		kutil_warn(r, NULL, "%s/%s: unlinkat", path, fn);
		errorpage(r, "Cannot remove \"%s\".", fn);
	} else {
		kutil_info(r, NULL, "%s/%s: unlink", path, fn);
		send_301(r);
	}
}

/*
 * Try to remove the current directory.
 * Send us to the directory above our own.
 */
static void
post_op_rmdir(int fd, const char *path, struct kreq *r)
{
	char	*newpath, *cp;

	if ('\0' == path[0]) {
		kutil_warn(r, NULL, "tried removing root");
		errorpage(r, "You cannot remove the root directory.");
		return;
	}

	if (-1 == unlinkat(fd, path, AT_REMOVEDIR) && ENOENT != errno) {
		kutil_warn(r, NULL, "%s: unlinkat (dir)", path);
		errorpage(r, "Cannot remove \"%s\".", path);
	} else {
		kutil_info(r, NULL, "%s: unlink (dir)", path);
		newpath = kstrdup(path);
		if (NULL != (cp = strrchr(newpath, '/')))
			*cp = '\0';
		else
			newpath[0] = '\0';
		send_301_path(r, newpath);
		free(newpath);
	}
}

/*
 * Make a directory "pn" relative to the current path "path" with file
 * descriptor "nfd".
 */
static void
post_op_mkdir(int nfd, const char *path,
	const char *pn, struct kreq *r)
{

	if (-1 == mkdirat(nfd, pn, 0700) && EEXIST != errno) {
		kutil_warn(r, NULL, "%s/%s: mkdirat", path, pn);
		errorpage(r, "Cannot create directory \"%s\".", pn);
	} else {
		kutil_info(r, NULL, "%s/%s: created", path, pn);
		send_301(r);
	}
}

/*
 * Write the file "fn" relative to the current path "path" with file
 * descriptor "nfd".
 * Use file contents "data" of size "sz".
 * FIXME: have this perform after closing the connection, else it might
 * block the connection.
 */
static void
post_op_mkfile(int nfd, const char *path,
	const char *fn, const char *data, 
	size_t sz, struct kreq *r)
{
	int	 dfd, fl = O_WRONLY|O_TRUNC|O_CREAT;
	ssize_t	 ssz;

	if (-1 == (dfd = openat(nfd, fn, fl, 0600))) {
		kutil_warn(r, NULL, "%s/%s: openat", path, fn);
		errorpage(r, "Cannot open \"%s\".", fn);
		return;
	}

	if ((ssz = write(dfd, data, sz)) < 0) {
		kutil_warn(r, NULL, "%s/%s: write", path, fn);
		errorpage(r, "Cannot write to file \"%s\".", fn);
	} else if ((size_t)ssz < sz) {
		kutil_warnx(r, NULL, "%s/%s: short write", path, fn);
		errorpage(r, "Cannot write to file \"%s\".", fn);
	} else {
		kutil_info(r, NULL, "%s/%s: wrote %zu bytes", 
			path, fn, sz);
		send_301(r);
	}

	close(dfd);
}

/*
 * Process an operation to make a file or directory.
 * This routes to either post_op_mkfile or post_op_mkdir.
 */
static void
post_op_file(int fd, const char *path, 
	enum action act, struct kreq *r)
{
	struct kpair	*kpf;
	int		 nfd = -1;
	int		 dfl = O_RDONLY|O_DIRECTORY;
	const char	*target;

	/* Start with validation. */

	if (ACTION_MKFILE == act &&
	    (NULL == r->fieldmap[KEY_FILE] ||
	     '\0' == r->fieldmap[KEY_FILE]->file[0])) {
		send_301(r);
		return;
	} 

	if (ACTION_RMFILE == act &&
	    NULL == r->fieldmap[KEY_FILENAME]) {
		send_301(r);
		return;
	}

	if (ACTION_MKDIR == act &&
	    NULL == r->fieldmap[KEY_DIR]) {
		send_301(r);
		return;
	}

	/* What we're working with. */

	target = ACTION_MKFILE == act ?
		r->fieldmap[KEY_FILE]->file :
		ACTION_RMFILE == act ?
		r->fieldmap[KEY_FILENAME]->parsed.s :
		ACTION_MKDIR == act ?
		r->fieldmap[KEY_DIR]->parsed.s : NULL;

	if (NULL != target &&
	    (NULL != strchr(target, '/') || '.' == target[0])) {
		errorpage(r, "File name security violation.");
		return;
	}

	/* Open the path we're writing into. */

	if ('\0' != path[0]) {
		if (-1 == (nfd = openat(fd, path, dfl, 0)))
			kutil_warn(r, NULL, "%s: openat", path);
	} else if (-1 == (nfd = dup(fd)))
		kutil_warn(r, NULL, "%s: dup", path);

	if (-1 == nfd) {
		errorpage(r, "Cannot open directory \"%s\".", path);
		goto out;
	}

	/* Now actually perform our operations. */

	if (ACTION_MKFILE == act) {
		kpf = r->fieldmap[KEY_FILE];
		post_op_mkfile(nfd, path, target, 
			kpf->val, kpf->valsz, r);
	} else if (ACTION_RMFILE == act) {
		post_op_rmfile(nfd, path, target, r);
	} else if (ACTION_RMDIR == act) {
		post_op_rmdir(fd, path, r);
	} else  {
		post_op_mkdir(nfd, path, target, r);
	}
out:
	if (-1 != nfd)
		close(nfd);
}

static void
post_op_logout(int authfd, const char *authpath, struct kreq *r)
{
	const char	*secure, *name;
	char		 buf[32];

	kutil_epoch2str(0, buf, sizeof(buf));
#ifdef SECURE
	secure = " secure;";
#else
	secure = "";
#endif
	name = r->cookiemap[KEY_SESSUSER]->parsed.s;

	if (-1 == unlinkat(authfd, name, 0))
		kutil_warn(r, name, "%s/%s", authpath, name);

	khttp_head(r, kresps[KRESP_SET_COOKIE],
		"%s=; path=/;%s HttpOnly; expires=%s", 
		keys[KEY_SESSCOOKIE].name, secure, buf);
	khttp_head(r, kresps[KRESP_SET_COOKIE],
		"%s=; path=/;%s HttpOnly; expires=%s", 
		keys[KEY_SESSUSER].name, secure, buf);
	send_301_path(r, "/");
	kutil_info(r, name, "user logged out");
}

static void
post_op_login(int authfd, const char *authpath, 
	const struct userq *uq, struct kreq *r)
{
	int	 	 fd;
	const char	*name, *pass, *secure;
	char		 buf[1024];
	const struct user *u;
	int64_t		 cookie;

	if (NULL == r->fieldmap[KEY_USER] ||
	    NULL == r->fieldmap[KEY_PASSWD]) {
		loginpage(r, LOGINERR_NOFIELD);
		return;
	}

	/*
	 * Look up the username, make sure it exists, then check against
	 * the given hash using the crypt_checkpass function, which does
	 * the heavy lefting for us.
	 */

	name = r->fieldmap[KEY_USER]->parsed.s;
	pass = r->fieldmap[KEY_PASSWD]->parsed.s;

	TAILQ_FOREACH(u, uq, entries)
		if (0 == strcasecmp(u->name, name))
			break;

	if (NULL == u) {
		kutil_warnx(r, NULL, "user not found: %s", name);
		loginpage(r, LOGINERR_BADCREDS);
		return;
	} else if (crypt_checkpass(pass, u->hash)) {
		kutil_warnx(r, name, "incorrect password");
		loginpage(r, LOGINERR_BADCREDS);
		return;
	}

	/*
	 * Create a random cookie (session token) and overwrite whatever
	 * is currently in our cookie file, if at all.
	 */

	cookie = arc4random();
	snprintf(buf, sizeof(buf), "%" PRId64 "\n", cookie);

	fd = openat(authfd, name, 
		O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (-1 == fd) {
		kutil_warn(r, NULL, "%s/%s", authpath, name);
		loginpage(r, LOGINERR_SYSERR);
		return;
	}
	if (write(fd, buf, strlen(buf)) < 0) {
		kutil_warn(r, NULL, "%s/%s", authpath, name);
		loginpage(r, LOGINERR_SYSERR);
		close(fd);
		return;
	}
	close(fd);

	/* Set our cookie and limit it to one year. */

#ifdef SECURE
	secure = " secure;";
#else
	secure = "";
#endif
	kutil_epoch2str
		(time(NULL) + 60 * 60 * 24 * 365,
		 buf, sizeof(buf));
	khttp_head(r, kresps[KRESP_SET_COOKIE],
		"%s=%" PRId64 ";%s HttpOnly; path=/; expires=%s", 
		keys[KEY_SESSCOOKIE].name, cookie, secure, buf);
	khttp_head(r, kresps[KRESP_SET_COOKIE],
		"%s=%s;%s HttpOnly; path=/; expires=%s", 
		keys[KEY_SESSUSER].name, name, secure, buf);
	send_301(r);

	kutil_info(r, name, "user logged in");
}

/*
 * Try to open the non-empty and relative directory "dir" within the
 * cache directory.
 * Return the file descriptor on success else -1.
 */
static int
open_dir(int cfd, const char *cache, const char *dir, struct kreq *r)
{
	int	 	 fd;

	if ('\0' == dir[0]) {
		kutil_warn(r, NULL, "empty directory");
		return(-1);
	} else if ('/' == dir[0]) {
		kutil_warn(r, NULL, "%s: absolute directory", dir);
		return(-1);
	}

	fd = openat(cfd, dir, O_RDONLY | O_DIRECTORY, 0);

	if (-1 == fd && ENOENT == errno) {
		kutil_info(r, NULL, "%s/%s: creating", cache, dir);
		if (-1 == mkdirat(cfd, dir, 0700)) {
			kutil_warn(r, NULL, "%s/%s: mkdir", cache, dir);
			return(-1);
		}
		fd = openat(cfd, dir, O_RDONLY | O_DIRECTORY, 0);
	}

	if (-1 == fd) {
		kutil_warn(r, NULL, "%s/%s: open", cache, dir);
		return(-1);
	}

	return(fd);
}

/*
 * Try to open the file ".htpasswd" within the cache directory opened as
 * "cfd" in "cache".
 * Return zero on fatal error, non-zero on success.
 * The "uq" will not be allocated if the file was not found; otherwise,
 * it will be allocated and filled with a (possibly-zero) user entries.
 * Note that "uq" might be allocated on failure.
 */
static int
open_users(struct userq **uq, 
	int cfd, const char *cache, struct kreq *r)
{
	int		 fd;
	FILE		*f;
	char		*buf;
	size_t		 len, line = 1;
	char		*user, *pass;
	struct user	*u;

	fd = openat(cfd, ".htpasswd", O_RDONLY, 0);

	if (-1 == fd && ENOENT != errno) {
		kutil_warn(r, NULL, "%s/.htpasswd: open", cache);
		return(0);
	} else if (-1 == fd) 
		return(1);

	if (NULL == (f = fdopen(fd, "r"))) {
		kutil_warn(r, NULL, "%s/.htpasswd: fopen", cache);
		close(fd);
		return(0);
	}

	*uq = kmalloc(sizeof(struct userq));
	TAILQ_INIT(*uq);

	while (NULL != (buf = fgetln(f, &len))) {
		if ('\n' != buf[len - 1])
			continue;
		buf[len - 1] = '\0';
		user = buf;
		if (NULL == (pass = strchr(user, ':'))) {
			kutil_warn(r, NULL, "%s/.htpasswd:%zu: "
				"malformed syntax", cache, line);
			fclose(f);
			return(0);
		}
		(*pass++) = '\0';
		u = kcalloc(1, sizeof(struct user));
		u->name = kstrdup(user);
		u->hash = kstrdup(pass);
		TAILQ_INSERT_TAIL(*uq, u, entries);
		line++;
	}

	fclose(f);
	return(1);
}

/*
 * Open our root directory, which must be absolute.
 * All operations will use "openat" or the equivalent beneath this path.
 * Returns the file descriptor or -1.
 */
static int
open_cachedir(const char *root, struct kreq *r)
{
	int	 	 fd;

	if ('\0' == root[0]) {
		kutil_warn(r, NULL, "empty cache directory");
		return(-1);
	} else if ('/' != root[0]) {
		kutil_warn(r, NULL, "%s: relative cache directory", root);
		return(-1);
	}

	fd = open(root, O_RDONLY | O_DIRECTORY, 0);

	if (-1 == fd && ENOENT == errno) {
		kutil_info(r, NULL, "%s: creating", root);
		if (-1 == mkdir(root, 0700)) {
			kutil_warn(r, NULL, "%s: mkdir", root);
			return(-1);
		}
		fd = open(root, O_RDONLY | O_DIRECTORY, 0);
	}

	if (-1 == fd) {
		kutil_warn(r, NULL, "%s: open", root);
		return(-1);
	}

	return(fd);
}

/*
 * Look in "dir" (opened as "fd") for the cookie registered to the
 * current user (who must exist) and cross-check its unique token.
 * Returns zero on failure, non-zero on success.
 */
static int
check_login(struct kreq *r, 
	const struct userq *uq, int fd, const char *dir) 
{
	const char	*name;
	int		 nfd;
	FILE		*f;
	int64_t		 cookie, ccookie;
	const struct user *u;

	assert(NULL != r->cookiemap[KEY_SESSCOOKIE]);
	assert(NULL != r->cookiemap[KEY_SESSUSER]);
	name = r->cookiemap[KEY_SESSUSER]->parsed.s;
	cookie = r->cookiemap[KEY_SESSCOOKIE]->parsed.i;

	/* Loop for user in known users. */

	TAILQ_FOREACH(u, uq, entries)
		if (0 == strcasecmp(u->name, name))
			break;

	if (NULL == u) {
		kutil_warnx(r, NULL, "unknown user: %s", name);
		return(0);
	}

	if (-1 == (nfd = openat(fd, name, O_RDONLY, 0))) {
		kutil_warn(r, NULL, "%s/%s", dir, name);
		return(0);
	}

	if (NULL == (f = fdopen(nfd, "r"))) {
		kutil_warn(r, NULL, "%s/%s", dir, name);
		close(nfd);
		return(0);
	} else if (1 != fscanf(f, "%" PRId64, &ccookie)) {
		kutil_warnx(r, NULL, "%s/%s: malformed", dir, name);
		fclose(f);
		return(0);
	}

	fclose(f);
	
	if (cookie != ccookie)
		kutil_warn(r, name, "cookie token mismatch");

	return(cookie == ccookie);
}

int
main(void)
{
	struct kreq	 r;
	enum kcgi_err	 er;
	int		 cachefd = -1, rc, isw, filefd = -1,
			 authfd = -1;
	enum ftype	 ftype = FTYPE_DIR;
	const char	*cp;
	char		*path = NULL;
	struct stat	 st;
	struct userq	*uq = NULL;
	struct user	*u;
	struct kpair	*kp;
	enum action	 act = ACTION__MAX;

	/* Log into a separate logfile (not system log). */

	kutil_openlog(LOGFILE);

	/* 
	 * Actually parse HTTP document.
	 * Then drop privileges to only have file-system access.
	 */

	er = khttp_parse(&r, keys, KEY__MAX, 
		pages, PAGE__MAX, PAGE_INDEX);

	if (KCGI_OK != er) {
		fprintf(stderr, "HTTP parse error: %d\n", er);
		return(EXIT_FAILURE);
	}

	if (-1 == pledge("rpath cpath wpath stdio", NULL)) {
		kutil_warn(&r, NULL, "pledge");
		goto out;
	}

	/*
	 * Front line of defence: make sure we're a proper method and
	 * make sure we're an HTML file.
	 */

	if (KMETHOD_GET != r.method && 
	    KMETHOD_POST != r.method) {
		errorpage(&r, "Invalid HTTP method.");
		goto out;
	}

	/* 
	 * Security: don't let us request a relative path.
	 * Then force to be relative and strip trailing slashes.
	 */

	if (NULL != strstr(r.fullpath, "/..") ||
	    ('\0' != r.fullpath[0] && '/' != r.fullpath[0])) {
		errorpage(&r, "Security violation in requested path.");
		goto out;
	} 

	path = kstrdup(r.fullpath);
	if ('\0' != path[0] && '/' == path[strlen(path) - 1])
		path[strlen(path) - 1] = '\0';
	cp = path;
	if ('/' == cp[0])
		cp++;

	/* Open files/directories: cache, cookies, files. */

	if (-1 == (cachefd = open_cachedir(CACHEDIR, &r))) {
		errorpage(&r, "Cannot open cache root.");
		goto out;
	}

	if ( ! open_users(&uq, cachefd, CACHEDIR, &r)) {
		errorpage(&r, "Cannot process password file.");
		goto out;
	}

	if (-1 == (filefd = open_dir
	    (cachefd, CACHEDIR, FILEDIR, &r))) {
		errorpage(&r, "Cannot open file root.");
		goto out;
	}

	if (-1 == (authfd = open_dir
	    (cachefd, CACHEDIR, AUTHDIR, &r))) {
		errorpage(&r, "Cannot open authorisation root.");
		goto out;
	}

	/* 
	 * Now figure out what we're supposed to do here.
	 * This will sanitise our request action.
	 * Then switch on those actions.
	 */

	if (KMETHOD_GET != r.method) {
		if (NULL == (kp = r.fieldmap[KEY_OP])) 
			act = ACTION__MAX;
		else if (0 == strcmp(kp->parsed.s, "mkfile"))
			act = ACTION_MKFILE;
		else if (0 == strcmp(kp->parsed.s, "rmfile"))
			act = ACTION_RMFILE;
		else if (0 == strcmp(kp->parsed.s, "rmdir"))
			act = ACTION_RMDIR;
		else if (0 == strcmp(kp->parsed.s, "mkdir"))
			act = ACTION_MKDIR;
		else if (0 == strcmp(kp->parsed.s, "login"))
			act = ACTION_LOGIN;
		else if (0 == strcmp(kp->parsed.s, "logout"))
			act = ACTION_LOGOUT;
	} else
		act = ACTION_GET;

	if (ACTION__MAX == act) {
		errorpage(&r, "Unspecified operation.");
		goto out;
	}

	/* Getting (readonly): drop privileges. */

	if (ACTION_GET == act)
		if (-1 == pledge("rpath stdio", NULL)) {
			kutil_warn(&r, NULL, "pledge");
			errorpage(&r, "System error.");
			goto out;
		}

	/* Logging in: jump straight to login page. */

	if (ACTION_LOGIN == act) {
		post_op_login(authfd, AUTHDIR, uq, &r);
		goto out;
	}

	/*
	 * We know what we want to do, but not whether we can.
	 * If we have users, check for session availability.
	 * If we don't have a session, or the session is a bad one, then
	 * kick us to the login page.
	 */

	if (NULL != uq)
		if (NULL == r.cookiemap[KEY_SESSCOOKIE] ||
		    NULL == r.cookiemap[KEY_SESSUSER] ||
		    ! check_login(&r, uq, authfd, AUTHDIR)) {
			loginpage(&r, LOGINERR_OK);
			goto out;
		}

	/* Logout only after session is validated. */

	if (ACTION_LOGOUT == act) {
		post_op_logout(authfd, AUTHDIR, &r);
		goto out;
	}

	/*
	 * See what kind of resource we're asking for by looking it up
	 * under the cache root.
	 * Disallow non-regular or directory files.
	 */

	rc = '\0' != cp[0] ? 
		fstatat(filefd, cp, &st, 0) : 
		fstat(filefd, &st);

	if (-1 == rc) {
		errorpage(&r, "Resource not found or unavailable.");
		goto out;
	}

	if (S_ISDIR(st.st_mode))
		ftype = FTYPE_DIR;
	else if (S_ISREG(st.st_mode))
		ftype = FTYPE_FILE;
	else
		ftype = FTYPE_OTHER;

	/*
	 * See if we have writable access to the resource.
	 * First check other status, then user, then primary group.
	 * If that fails, look in our supplemental groups.
	 */

	if ((isw = check_canwrite(&st)) < 0) {
		kutil_warn(&r, NULL, "getgroups");
		errorpage(&r, "System error.");
		goto out;
	}

	/*
	 * If we're a GET, then either list the directory contents or
	 * post the given file to output.
	 * If we're a POST, then process the post (it must be into a
	 * directory) and reload.
	 */

	if (ACTION_GET == act) {
		if (FTYPE_DIR == ftype)
			get_dir(filefd, cp, isw, &r, NULL != uq);
		else
			get_file(filefd, cp, &r);
	} else {
		if (FTYPE_DIR != ftype)
			errorpage(&r, "Post into a regular file.");
		else if ( ! isw)
			errorpage(&r, "Post into readonly directory.");
		else
			post_op_file(filefd, cp, act, &r);
	}

out:
	/* Drop privileges and free memory. */

	if (-1 == pledge("stdio", NULL))
		kutil_warn(&r, NULL, "pledge");

	if (NULL != uq) {
		while (NULL != (u = TAILQ_FIRST(uq))) {
			TAILQ_REMOVE(uq, u, entries);
			free(u->name);
			free(u->hash);
			free(u);
		}
		free(uq);
	}

	free(path);
	if (-1 != cachefd)
		close(cachefd);
	if (-1 != filefd)
		close(filefd);
	if (-1 != authfd)
		close(authfd);
	khttp_free(&r);
	return(EXIT_SUCCESS);
}
