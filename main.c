/*	$Id$ */
#include <sys/queue.h>
#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <kcgi.h>
#include <kcgihtml.h>

#define	FONT_AWESOME_URL \
	"https://maxcdn.bootstrapcdn.com/" \
	"font-awesome/4.7.0/css/font-awesome.min.css"

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

enum	key {
	KEY_DIR,
	KEY_FILE,
	KEY_FILENAME,
	KEY_OP,
	KEY_SESSCOOKIE,
	KEY_SESSUSER,
	KEY__MAX
};

enum	ftype {
	FTYPE_DIR, /* directory */
	FTYPE_FILE, /* regular file */
	FTYPE_OTHER
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

static const char *const pages[PAGE__MAX] = {
	"index", /* PAGE_INDEX */
};

static const struct kvalid keys[KEY__MAX] = {
	{ kvalid_stringne, "dir" }, /* KEY_DIR */
	{ NULL, "file" }, /* KEY_FILE */
	{ kvalid_stringne, "filename" }, /* KEY_FILENAME */
	{ kvalid_stringne, "op" }, /* KEY_OP */
	{ kvalid_int, "stok" }, /* KEY_SESSCOOKIE */
	{ kvalid_stringne, "suser" }, /* KEY_SESSUSER */
};

static void
errorpage(struct kreq *, const char *, ...) 
	__attribute__((format(printf, 2, 3)));

/*
 * Fill out all HTTP secure headers.
 * Use the existing document's MIME type.
 */
static void
http_alloc(struct kreq *r, enum khttp code)
{

	khttp_head(r, kresps[KRESP_STATUS], 
		"%s", khttps[code]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE], 
		"%s", kmimetypes[r->mime]);
	khttp_head(r, "X-Content-Type-Options", "nosniff");
	khttp_head(r, "X-Frame-Options", "DENY");
	khttp_head(r, "X-XSS-Protection", "1; mode=block");
}

/*
 * Fill out all headers with http_alloc() then start the HTTP document
 * body (no more headers after this point!)
 */
static void
http_open(struct kreq *r, enum khttp code)
{

	http_alloc(r, code);
	khttp_body(r);
}

static int
loginpage_template(size_t index, void *arg)
{
	struct kreq	*r = arg;

	if (index > 0)
		return(0);

	khttp_puts(r, r->fullpath);
	return(1);
}

static void
loginpage(struct kreq *r)
{
	struct ktemplate t;
	const char	*ts = "URL";

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = &ts;
	t.keysz = 1;
	t.arg = r;
	t.cb = loginpage_template;
	http_open(r, KHTTP_200);
	khttp_template(r, &t, DATADIR "loginpage.xml");
}

static void
errorpage(struct kreq *r, const char *fmt, ...)
{
	struct khtmlreq	 req;
	char		*buf;
	va_list		 ap;

	va_start(ap, fmt);
	if (-1 == vasprintf(&buf, fmt, ap))
		exit(EXIT_FAILURE);
	va_end(ap);

	http_open(r, KHTTP_200);
	khtml_open(&req, r, KHTML_PRETTY);
	khtml_elem(&req, KELEM_DOCTYPE);
	khtml_attr(&req, KELEM_HTML,
		KATTR_LANG, "en",
		KATTR__MAX);
	khtml_elem(&req, KELEM_HEAD);
	khtml_attr(&req, KELEM_META,
		KATTR_CHARSET, "utf-8",
		KATTR__MAX);
	khtml_attr(&req, KELEM_META,
		KATTR_NAME, "viewport",
		KATTR_CONTENT, "width=device-width, initial-scale=1",
		KATTR__MAX);
	khtml_elem(&req, KELEM_TITLE);
	khtml_puts(&req, "Error");
	khtml_closeelem(&req, 1);
	khtml_attr(&req, KELEM_LINK,
		KATTR_HREF, HTURI "bulma.css",
		KATTR_REL, "stylesheet",
		KATTR__MAX);
	khtml_attr(&req, KELEM_LINK,
		KATTR_HREF, FONT_AWESOME_URL,
		KATTR_REL, "stylesheet",
		KATTR__MAX);
	khtml_attr(&req, KELEM_LINK,
		KATTR_HREF, HTURI "httpdrop.css",
		KATTR_REL, "stylesheet",
		KATTR__MAX);
	khtml_closeelem(&req, 1);
	khtml_attr(&req, KELEM_BODY,
		KATTR_CLASS, "errorpage",
		KATTR__MAX);
	khtml_attr(&req, KELEM_SECTION,
		KATTR_CLASS, "hero is-danger is-fullheight",
		KATTR__MAX);
	khtml_attr(&req, KELEM_DIV,
		KATTR_CLASS, "hero-body",
		KATTR__MAX);
	khtml_attr(&req, KELEM_DIV,
		KATTR_CLASS, "container",
		KATTR__MAX);
	khtml_attr(&req, KELEM_H1,
		KATTR_CLASS, "title",
		KATTR__MAX);
	khtml_puts(&req, "Error");
	khtml_closeelem(&req, 1);
	khtml_attr(&req, KELEM_H2,
		KATTR_CLASS, "subtitle",
		KATTR__MAX);
	khtml_puts(&req, buf);
	khtml_closeelem(&req, 6);
	khtml_close(&req);
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

static int
get_dir_template(size_t index, void *arg)
{
	struct kreq	*r = arg;

	if (index > 0)
		return(0);

	khttp_puts(r, r->fullpath);
	return(1);
}

/*
 * Print a directory listing.
 * This is preceded by the form for directory creation and file upload.
 * FIXME: use directory mtime and cache control.
 */
static void
get_dir(int fd, const char *path, int rdwr, struct kreq *r)
{
	int		 nfd;
	struct stat	 st;
	char		*fpath;
	DIR		*dir;
	struct dirent	*dp;
	int		 fl = O_RDONLY | O_DIRECTORY;
	struct khtmlreq	 req;
	size_t		 sz = 0, filesz = 0, rfilesz = 0, i;
	struct ktemplate t;
	const char	*ts = "URL";
	struct fref	*files = NULL;
	const struct fref *ff;

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

	/*
	 * No more errors reported.
	 * Print all of our entities along with a header allowing us to
	 * upload more files.
	 */

	http_open(r, KHTTP_200);
	khtml_open(&req, r, KHTML_PRETTY);
	khtml_elem(&req, KELEM_DOCTYPE);

	khtml_attr(&req, KELEM_HTML,
		KATTR_LANG, "en",
		KATTR__MAX);
	khtml_elem(&req, KELEM_HEAD);
	khtml_attr(&req, KELEM_META,
		KATTR_CHARSET, "utf-8",
		KATTR__MAX);
	khtml_attr(&req, KELEM_META,
		KATTR_NAME, "viewport",
		KATTR_CONTENT, "width=device-width, initial-scale=1",
		KATTR__MAX);
	khtml_elem(&req, KELEM_TITLE);
	khtml_puts(&req, "Directory listing");
	khtml_closeelem(&req, 1);
	khtml_attr(&req, KELEM_LINK,
		KATTR_HREF, HTURI "bulma.css",
		KATTR_REL, "stylesheet",
		KATTR__MAX);
	khtml_attr(&req, KELEM_LINK,
		KATTR_HREF, FONT_AWESOME_URL,
		KATTR_REL, "stylesheet",
		KATTR__MAX);
	khtml_attr(&req, KELEM_LINK,
		KATTR_HREF, HTURI "httpdrop.css",
		KATTR_REL, "stylesheet",
		KATTR__MAX);
	khtml_attr(&req, KELEM_SCRIPT,
		KATTR_SRC, HTURI "httpdrop.js",
		KATTR__MAX);
	khtml_closeelem(&req, 2);

	/*
	 * If the current directory has write permissions, note this as
	 * our body class so that children can configure themselves.
	 */

	khtml_attr(&req, KELEM_BODY,
		KATTR_CLASS, 
			rdwr && rfilesz > 0 ? 
			"mutable nonempty" :
			rdwr && 0 == rfilesz ?
			"mutable empty" :
			0 == rdwr && rfilesz > 0 ?
			"immutable nonempty" :
			"immutable empty",
		KATTR__MAX);
	khtml_attr(&req, KELEM_SECTION,
		KATTR_CLASS, "section",
		KATTR__MAX);
	khtml_attr(&req, KELEM_DIV,
		KATTR_CLASS, "container",
		KATTR__MAX);

	if (filesz)
		khtml_elem(&req, KELEM_UL);

	for (i = 0; i < filesz; i++) {
		ff = &files[i];
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

		if (rdwr && ! (S_ISDIR(ff->st.st_mode))) {
			khtml_attr(&req, KELEM_FORM,
				KATTR_METHOD, "post",
				KATTR_CLASS, "icon",
				KATTR_ACTION, fpath,
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
			if ((S_IWUSR|S_IWGRP|S_IWOTH) & 
			    ff->st.st_mode)
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
		sz++;
	}

	if (0 == filesz) {
		khtml_elem(&req, KELEM_P);
		khtml_puts(&req, 
			"No files or directories to list. "
			"Time to create or upload some?");
		khtml_closeelem(&req, 1);
	} else {
		khtml_closeelem(&req, 1);
	}

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = &ts;
	t.keysz = 1;
	t.arg = r;
	t.cb = get_dir_template;

	khtml_closeelem(&req, 1);
	khttp_template(r, &t, DATADIR "httpdrop.xml");
	khtml_closeelem(&req, 3);
	khtml_close(&req);

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

	khttp_head(r, kresps[KRESP_STATUS], 
		"%s", khttps[KHTTP_200]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE], 
		"%s", kmimetypes[r->mime]);
	khttp_head(r, "X-Content-Type-Options", "nosniff");
	khttp_head(r, "X-Frame-Options", "DENY");
	khttp_head(r, "X-XSS-Protection", "1; mode=block");
	khttp_body(r);
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

	kasprintf(&path, "%s%s", r->pname, fullpath);
	np = kutil_urlabs(r->scheme, r->host, r->port, path);
	free(path);

	khttp_head(r, kresps[KRESP_STATUS], 
		"%s", khttps[KHTTP_303]);
        khttp_head(r, kresps[KRESP_CONTENT_TYPE], 
		"%s", kmimetypes[r->mime]);
	khttp_head(r, kresps[KRESP_LOCATION], 
		"%s", np);
	khttp_body(r);
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
		newpath = kstrdup(r->fullpath);
		if (NULL != (cp = strrchr(newpath, '/')))
			*cp = '\0';
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
post_op(int fd, const char *path, struct kreq *r)
{
	struct kpair	*kp, *kpf;
	int		 nfd = -1;
	int		 dfl = O_RDONLY|O_DIRECTORY;
	const char	*target;

	/* Start with validation. */

	if (NULL == (kp = r->fieldmap[KEY_OP]) ||
	    (strcmp(kp->parsed.s, "mkfile") &&
	     strcmp(kp->parsed.s, "rmfile") &&
	     strcmp(kp->parsed.s, "rmdir") &&
	     strcmp(kp->parsed.s, "mkdir"))) {
		errorpage(r, "Unknown file operation.");
		return;
	} 

	if (0 == strcmp(kp->parsed.s, "mkfile") &&
	    (NULL == r->fieldmap[KEY_FILE] ||
	     '\0' == r->fieldmap[KEY_FILE]->file[0])) {
		send_301(r);
		return;
	} 

	if (0 == strcmp(kp->parsed.s, "rmfile") &&
	    NULL == r->fieldmap[KEY_FILENAME]) {
		send_301(r);
		return;
	}

	if (0 == strcmp(kp->parsed.s, "mkdir") &&
	    NULL == r->fieldmap[KEY_DIR]) {
		send_301(r);
		return;
	}

	/* What we're working with. */

	target = 0 == strcmp(kp->parsed.s, "mkfile") ?
		r->fieldmap[KEY_FILE]->file :
		0 == strcmp(kp->parsed.s, "rmfile") ?
		r->fieldmap[KEY_FILENAME]->parsed.s :
		0 == strcmp(kp->parsed.s, "mkdir") ?
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

	if (0 == strcmp(kp->parsed.s, "mkfile")) {
		kpf = r->fieldmap[KEY_FILE];
		post_op_mkfile(nfd, path, target, 
			kpf->val, kpf->valsz, r);
	} else if (0 == strcmp(kp->parsed.s, "rmfile")) {
		post_op_rmfile(nfd, path, target, r);
	} else if (0 == strcmp(kp->parsed.s, "rmdir")) {
		post_op_rmdir(fd, path, r);
	} else  {
		post_op_mkdir(nfd, path, target, r);
	}
out:
	if (-1 != nfd)
		close(nfd);
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

	kutil_info(r, NULL, "%s/.htpasswd: using passwords", cache);

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
		kutil_info(r, NULL, "%s/.htpasswd: %s, %s", cache, user, pass);
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

	/* Log into a separate logfile (not system log). */

	kutil_openlog(LOGFILE);

	/* Actually parse HTTP document. */

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

	/* Security: don't let us request a relative path. */

	if (NULL != strstr(r.fullpath, "/..") ||
	    ('\0' != r.fullpath[0] && '/' != r.fullpath[0])) {
		errorpage(&r, "Security violation in path name.");
		goto out;
	} 

	/*
	 * See what kind of file we're asking for by looking it up under
	 * the cache root.
	 * Disallow non-regular or directory files.
	 * Force it to be relative and strip any trailing slashes.
	 */

	path = kstrdup(r.fullpath);
	if ('\0' != path[0] && '/' == path[strlen(path) - 1])
		path[strlen(path) - 1] = '\0';
	cp = path;
	if ('/' == cp[0])
		cp++;

	/* Open our cache directory. */

	if (-1 == (cachefd = open_cachedir(CACHEDIR, &r))) {
		errorpage(&r, "Cannot open cache root.");
		goto out;
	}

	/* Do we have any permissions? */

	if ( ! open_users(&uq, cachefd, CACHEDIR, &r)) {
		errorpage(&r, "Cannot process password file.");
		goto out;
	}

	/* Open our files and auth (cookies) directory. */

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
	 * Now all directories have been created that need creating and,
	 * if we're a GET request, we can drop the privilege to create
	 * new things.
	 */

	if (KMETHOD_GET == r.method) 
		if (-1 == pledge("rpath stdio", NULL)) {
			kutil_warn(&r, NULL, "pledge");
			goto out;
		}

	/*
	 * We have users, which means we need to check for session
	 * availability.
	 */

	if (NULL != uq) {
		if (NULL == r.cookiemap[KEY_SESSCOOKIE] ||
		    NULL == r.cookiemap[KEY_SESSUSER]) {
			loginpage(&r);
			goto out;
		}
	}

	/*
	 * We're logged in and ready to process the request.
	 * Here we go!
	 */

	rc = '\0' != cp[0] ? 
		fstatat(filefd, cp, &st, 0) : 
		fstat(filefd, &st);

	if (-1 == rc) {
		errorpage(&r, "Requested \"%s\" "
			"not found or unavailable.", cp);
		goto out;
	}

	if (S_ISDIR(st.st_mode))
		ftype = FTYPE_DIR;
	else if (S_ISREG(st.st_mode))
		ftype = FTYPE_FILE;
	else
		ftype = FTYPE_OTHER;

	/*
	 * We need to be a regular file or a directory.
	 * If we're a directory, we need execute access for our user.
	 */

	if (FTYPE_OTHER == ftype || (FTYPE_DIR && 
	     ! ((S_IXUSR|S_IXGRP|S_IXOTH) & st.st_mode))) {
		errorpage(&r, "Requested \"%s\" "
			"not found or unavailable.", cp);
		goto out;
	} 

	isw = (S_IWUSR|S_IWGRP|S_IWOTH) & st.st_mode;

	/*
	 * If we're a GET, then either list the directory contents or
	 * post the given file to output.
	 * If we're a POST, then process the post (it must be into a
	 * directory) and reload.
	 */

	if (KMETHOD_GET == r.method) {
		if (FTYPE_DIR == ftype)
			get_dir(filefd, cp, isw, &r);
		else
			get_file(filefd, cp, &r);
	} else {
		assert(KMETHOD_POST == r.method);
		if (FTYPE_DIR != ftype)
			errorpage(&r, "Post into a regular file.");
		else if ( ! isw)
			errorpage(&r, "Post into readonly directory.");
		else
			post_op(filefd, cp, &r);
	}

out:
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
