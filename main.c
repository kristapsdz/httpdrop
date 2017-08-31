/*	$Id$ */
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

enum	page {
	PAGE_INDEX,
	PAGE__MAX
};

enum	key {
	KEY_DIR,
	KEY_FILE,
	KEY_FILENAME,
	KEY_OP,
	KEY__MAX
};

enum	ftype {
	FTYPE_DIR,
	FTYPE_FILE,
	FTYPE_OTHER
};

static const char *const pages[PAGE__MAX] = {
	"index", /* PAGE_INDEX */
};

static const struct kvalid keys[KEY__MAX] = {
	{ kvalid_stringne, "dir" }, /* KEY_DIR */
	{ NULL, "file" }, /* KEY_FILE */
	{ kvalid_stringne, "filename" }, /* KEY_FILENAME */
	{ kvalid_stringne, "op" } /* KEY_OP */
};

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

static void
errorpage(struct kreq *r, const char *msg)
{
	struct khtmlreq	 req;

	http_open(r, KHTTP_200);
	khtml_open(&req, r, KHTML_PRETTY);
	khtml_elem(&req, KELEM_P);
	khtml_puts(&req, msg);
	khtml_close(&req);
}

static int
scan_dir_template(size_t index, void *arg)
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
 */
static void
get_dir(int fd, const char *path, int rdwr, struct kreq *r)
{
	int		 nfd;
	struct stat	 st;
	char		*bufp, *fpath;
	DIR		*dir;
	struct dirent	*dp;
	int		 fl = O_RDONLY | O_DIRECTORY;
	struct khtmlreq	 req;
	size_t		 sz = 0;
	struct ktemplate t;
	const char	*ts = "URL";

	if ('\0' != path[0]) {
		if (-1 == (nfd = openat(fd, path, fl, 0)))
			kutil_warn(r, NULL, "%s: openat", path);
	} else if (-1 == (nfd = dup(fd)))
		kutil_warn(r, NULL, "%s: dup", path);

	if (-1 == nfd) {
		errorpage(r, "Cannot open directory.");
		return;
	}

	/* Get the DIR pointer from the directory request. */

	if (NULL == (dir = fdopendir(nfd))) {
		kutil_warn(r, NULL, "%s: fdopendir", path);
		errorpage(r, "Cannot open directory.");
		return;
	}

	kasprintf(&fpath, "%s/%s%s", r->pname, path, 
		'\0' != path[0] ? "/" : "");

	/*
	 * No more errors reported.
	 * Print all of our entities along with a header allowing us to
	 * upload more files.
	 */

	khttp_head(r, kresps[KRESP_STATUS], 
		"%s", khttps[KHTTP_200]);
	khttp_head(r, kresps[KRESP_CONTENT_TYPE], 
		"%s", kmimetypes[r->mime]);
	khttp_head(r, "X-Content-Type-Options", "nosniff");
	khttp_head(r, "X-Frame-Options", "DENY");
	khttp_head(r, "X-XSS-Protection", "1; mode=block");
	khttp_body(r);

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
		KATTR_CLASS, (rdwr ? "mutable" : "immutable"),
		KATTR__MAX);
	khtml_attr(&req, KELEM_SECTION,
		KATTR_CLASS, "section",
		KATTR__MAX);
	khtml_attr(&req, KELEM_DIV,
		KATTR_CLASS, "container",
		KATTR__MAX);
	while (NULL != (dp = readdir(dir))) {
		/* Only allow regular files. */
		if (DT_DIR != dp->d_type && 
		    DT_REG != dp->d_type)
			continue;
		if (0 == strcmp(dp->d_name, "."))
			continue;
		/* Do not print the ".." in the root directory. */
		if (0 == strcmp(dp->d_name, "..") &&
		    '\0' == path[0])
			continue;
		/* Get file information... */
		if (-1 == fstatat(nfd, dp->d_name, &st, 0))
			continue;

		if (0 == sz)
			khtml_elem(&req, KELEM_UL);

		kasprintf(&bufp, "%s/%s%s%s", r->pname, path, 
			'\0' != path[0] ? "/" : "", dp->d_name);

		/* Print link and ctime. */

		khtml_elem(&req, KELEM_LI);
		khtml_attr(&req, KELEM_A,
			KATTR_HREF, bufp, 
			KATTR__MAX);
		khtml_puts(&req, dp->d_name);
		if (DT_DIR == dp->d_type)
			khtml_puts(&req, "/");
		khtml_closeelem(&req, 1);

		khtml_elem(&req, KELEM_SPAN);
		if (DT_DIR == dp->d_type) {
			khtml_puts(&req, "");
		} else if (st.st_size > 1024 * 1024 * 1024) {
			khtml_int(&req, st.st_size / 1024/1024/1024);
			khtml_puts(&req, " GB");
		} else if (st.st_size > 1024 * 1024) {
			khtml_int(&req, st.st_size / 1024/1024);
			khtml_puts(&req, " MB");
		} else if (st.st_size > 1024) {
			khtml_int(&req, st.st_size / 1024);
			khtml_puts(&req, " KB");
		} else {
			khtml_int(&req, st.st_size);
			khtml_puts(&req, " B");
		}
		khtml_closeelem(&req, 1);

		khtml_elem(&req, KELEM_SPAN);
		khtml_puts(&req, ctime(&st.st_ctim.tv_sec));
		khtml_closeelem(&req, 1);

		if (rdwr && DT_DIR != dp->d_type) {
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
				KATTR_VALUE, dp->d_name,
				KATTR__MAX);
			khtml_attr(&req, KELEM_DIV,
				KATTR_CLASS, "field is-small",
				KATTR__MAX);
			khtml_attr(&req, KELEM_BUTTON,
				KATTR_CLASS, "button is-danger is-outlined",
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
		free(bufp);
		sz++;
	}

	if (0 == sz) {
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
	t.cb = scan_dir_template;

	khtml_closeelem(&req, 1);
	khttp_template(r, &t, DATADIR "httpdrop.xml");
	khtml_closeelem(&req, 3);
	khtml_close(&req);

	closedir(dir);
	free(fpath);
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
		errorpage(r, "Cannot open file.");
		return;
	}

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
send_301(struct kreq *r)
{
	char	*np, *path;

	kasprintf(&path, "%s%s", r->pname, r->fullpath);
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
 * Unlink a regular file "fn" relative to the current path "path" with
 * file descriptor "nfd".
 */
static void
post_op_rmfile(int nfd, const char *path,
	const char *fn, struct kreq *r)
{

	if (-1 == unlinkat(nfd, fn, 0) && ENOENT != errno) {
		kutil_warn(r, NULL, "%s/%s: unlinkat", path, fn);
		errorpage(r, "System failure (unlinkat).");
	} else {
		kutil_info(r, NULL, "%s/%s: unlink", path, fn);
		send_301(r);
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
		errorpage(r, "System failure (mkdir).");
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
		errorpage(r, "System failure (open).");
		return;
	}

	if ((ssz = write(dfd, data, sz)) < 0) {
		kutil_warn(r, NULL, "%s/%s: write", path, fn);
		errorpage(r, "System failure (write).");
	} else if ((size_t)ssz < sz) {
		kutil_warnx(r, NULL, "%s/%s: short write", path, fn);
		errorpage(r, "System failure (short write).");
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
	     strcmp(kp->parsed.s, "mkdir"))) {
		errorpage(r, "Unknown operation.");
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
		r->fieldmap[KEY_DIR]->parsed.s;

	if (NULL != strchr(target, '/') || '.' == target[0]) {
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
		errorpage(r, "Cannot open directory.");
		goto out;
	}

	/* Now actually perform our operations. */

	if (0 == strcmp(kp->parsed.s, "mkfile")) {
		kpf = r->fieldmap[KEY_FILE];
		post_op_mkfile(nfd, path, target, 
			kpf->val, kpf->valsz, r);
	} else if (0 == strcmp(kp->parsed.s, "rmfile")) {
		post_op_rmfile(nfd, path, target, r);
	} else  {
		post_op_mkdir(nfd, path, target, r);
	}
out:
	if (-1 != nfd)
		close(nfd);
}

/*
 * Open our root directory.
 * All operations will use "openat" or the equivalent beneath this path.
 * Returns the file descriptor or -1.
 */
static int
open_cachedir(struct kreq *r)
{
	int	 	 fd;
	const char	*root = CACHE;

	fd = open(root, O_RDONLY | O_DIRECTORY, 0);

	if (-1 == fd && ENOENT == errno) {
		kutil_info(r, NULL, "%s: creating", root);
		if (-1 == mkdir(root, 0700)) {
			kutil_warn(r, NULL, "%s: mkdir", root);
			errorpage(r, "Could not create cache.");
			return(-1);
		}
		fd = open(root, O_RDONLY | O_DIRECTORY, 0);
	}

	if (-1 == fd) {
		kutil_warn(r, NULL, "%s: open", root);
		errorpage(r, "Could not open cache.");
		return(-1);
	}

	return(fd);
}

int
main(void)
{
	struct kreq	 r;
	enum kcgi_err	 er;
	int		 fd = -1, rc;
	enum ftype	 ftype = FTYPE_DIR;
	const char	*cp;
	char		*path = NULL;
	struct stat	 st;

	/* Log into a separate logfile (not system log). */

	kutil_openlog(LOGFILE);

	/* Actually parse HTTP document. */

	er = khttp_parse(&r, keys, KEY__MAX, 
		pages, PAGE__MAX, PAGE_INDEX);

	if (KCGI_OK != er) {
		fprintf(stderr, "HTTP parse error: %d\n", er);
		return(EXIT_FAILURE);
	}

	/*
	 * Front line of defence: make sure we're a proper method and
	 * make sure we're an HTML file.
	 */

	if (KMETHOD_GET != r.method && 
	    KMETHOD_POST != r.method) {
		errorpage(&r, "Incorrect HTTP method.");
		goto out;
	}

	/* Security: don't let us request a relative path. */

	if (NULL != strstr(r.fullpath, "/..") ||
	    ('\0' != r.fullpath[0] && '/' != r.fullpath[0])) {
		errorpage(&r, "Security violation in path name.");
		goto out;
	} 

	/* Open our cache directory. */

	if (-1 == (fd = open_cachedir(&r)))
		goto out;

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

	rc = '\0' != cp[0] ? fstatat(fd, cp, &st, 0) : fstat(fd, &st);

	if (-1 == rc) {
		errorpage(&r, "Requested entity not found.");
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

	if (FTYPE_OTHER == ftype || 
	    (FTYPE_DIR && ! (S_IXUSR & st.st_mode))) {
		errorpage(&r, "Invalid requested entity.");
		goto out;
	} 

	/*
	 * If we're a GET, then either list the directory contents or
	 * post the given file to output.
	 * If we're a POST, then process the post (it must be into a
	 * directory) and reload.
	 */

	if (KMETHOD_GET == r.method) {
		if (FTYPE_DIR == ftype)
			get_dir(fd, cp, S_IWUSR & st.st_mode, &r);
		else
			get_file(fd, cp, &r);
	} else {
		assert(KMETHOD_POST == r.method);
		if (FTYPE_DIR != ftype)
			errorpage(&r, "Post into a regular file.");
		else if ( ! (S_IWUSR & st.st_mode))
			errorpage(&r, "Post into readonly directory");
		else
			post_op(fd, cp, &r);
	}

out:
	free(path);
	if (-1 != fd)
		close(fd);
	khttp_free(&r);
	return(EXIT_SUCCESS);
}
