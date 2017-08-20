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
	{ kvalid_stringne, "dir" },
	{ NULL, "file" },
	{ kvalid_stringne, "op" }
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

/*
 * Print a directory listing.
 * This is preceded by the form for directory creation and file upload.
 */
static void
scan_dir(int fd, const char *path, struct kreq *r)
{
	int		 nfd;
	struct stat	 st;
	char		*bufp;
	DIR		*dir;
	struct dirent	*dp;
	int		 fl = O_RDONLY | O_DIRECTORY;
	struct khtmlreq	 req;
	size_t		 sz = 0;

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
	khtml_elem(&req, KELEM_BODY);
	khtml_attr(&req, KELEM_SECTION,
		KATTR_CLASS, "section",
		KATTR__MAX);
	khtml_attr(&req, KELEM_DIV,
		KATTR_CLASS, "container",
		KATTR__MAX);
	khtml_elem(&req, KELEM_P);
	khtml_puts(&req, 
		"All files and folders are listed below. "
		"Create more by using the controls at the bottom.");
	khtml_closeelem(&req, 2);
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

		khtml_closeelem(&req, 1);
		free(bufp);
		sz++;
	}

	if (0 == sz) {
		khtml_elem(&req, KELEM_P);
		khtml_puts(&req, "No files or directories to list.");
		khtml_puts(&req, "Time to create or upload some?");
		khtml_closeelem(&req, 1);
	} else {
		khtml_closeelem(&req, 1);
	}

	khtml_closeelem(&req, 1);
	khttp_template(r, NULL, DATADIR "httpdrop.xml");
	khtml_closeelem(&req, 3);
	khtml_close(&req);

	closedir(dir);
}

/*
 * Grok a file.
 * All we do use is the template feature to print out.
 */
static void
scan_file(int fd, const char *path, struct kreq *r)
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
 * Process an operation to make a file or directory.
 */
static void
post_op(int fd, const char *path, struct kreq *r)
{
	struct kpair	*kp, *kpf;
	ssize_t		 ssz;
	int		 nfd = -1, dfd = -1;
	int		 fl = O_WRONLY|O_TRUNC|O_CREAT,
			 dfl = O_RDONLY|O_DIRECTORY;
	const char	*target;

	/* Start with validation. */

	if (NULL == (kp = r->fieldmap[KEY_OP]) ||
	    (strcmp(kp->parsed.s, "mkfile") &&
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

	if (0 == strcmp(kp->parsed.s, "mkdir") &&
	    NULL == r->fieldmap[KEY_DIR]) {
		send_301(r);
		return;
	}

	/* What we're working with. */

	target = 0 == strcmp(kp->parsed.s, "mkfile") ?
		r->fieldmap[KEY_FILE]->file :
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
		if (-1 == (dfd = openat(nfd, target, fl, 0600))) {
			kutil_warn(r, NULL, "%s: openat", target);
			errorpage(r, "System failure (open).");
			goto out;
		}

		/* FIXME: use some sort of polling...? */

		if ((ssz = write(dfd, kpf->val, kpf->valsz)) < 0) {
			kutil_warn(r, NULL, "%s: write", target);
			errorpage(r, "System failure (write).");
			goto out;
		} else if ((size_t)ssz < kpf->valsz) {
			kutil_warnx(r, NULL, "%s: short write", target);
			errorpage(r, "System failure (short write).");
			goto out;
		}
		kutil_info(r, NULL, "%s/%s: wrote %zu bytes", 
			path, target, kpf->valsz);
	} else {
		assert(0 == strcmp(kp->parsed.s, "mkdir"));
		if (-1 == mkdirat(nfd, target, 0700) && 
		    EEXIST != errno) {
			kutil_warn(r, NULL, "%s: mkdirat", target);
			errorpage(r, "System failure (mkdir).");
			goto out;
		}
		kutil_info(r, NULL, "%s/%s: created", path, target);
	}

	/* On success, reload the calling page. */

	send_301(r);
out:
	if (-1 != nfd)
		close(nfd);
	if (-1 != dfd)
		close(dfd);
}

int
main(void)
{
	struct kreq	 r;
	enum kcgi_err	 er;
	int		 fd = -1;
	enum ftype	 ftype;
	const char	*root = CACHE, *cp;
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

	/*
	 * Open our root directory.
	 * All operations will use "openat" or the equivalent beneath
	 * this path.
	 */

	fd = open(root, O_RDONLY | O_DIRECTORY, 0);

	if (-1 == fd && ENOENT == errno) {
		kutil_info(&r, NULL, "%s: creating", root);
		if (-1 == mkdir(root, 0700)) {
			kutil_warn(&r, NULL, "%s: mkdir", root);
			errorpage(&r, "Could not create cache.");
			goto out;
		}
		fd = open(root, O_RDONLY | O_DIRECTORY, 0);
	}

	if (-1 == fd) {
		kutil_warn(&r, NULL, "%s: open", root);
		errorpage(&r, "Could not open cache.");
		goto out;
	}

	ftype = FTYPE_DIR;

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

	if ('\0' != cp[0]) {
		if (-1 == fstatat(fd, cp, &st, 0)) {
			errorpage(&r, "Requested entity not found.");
			goto out;
		}
		if (S_ISDIR(st.st_mode))
			ftype = FTYPE_DIR;
		else if (S_ISREG(st.st_mode))
			ftype = FTYPE_FILE;
		else
			ftype = FTYPE_OTHER;
	} 

	if (FTYPE_OTHER == ftype) {
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
			scan_dir(fd, cp, &r);
		else
			scan_file(fd, cp, &r);
	} else {
		assert(KMETHOD_POST == r.method);
		if (FTYPE_DIR != ftype)
			errorpage(&r, "Post into a regular file.");
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
