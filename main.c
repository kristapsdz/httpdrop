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
#include <zip.h>

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
	ACTION_GETZIP,
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

enum	templ {
	TEMPL_URL,
	TEMPL_CLASSES,
	TEMPL_USER,
	TEMPL_MESSAGE,
	TEMPL_FILES,
	TEMPL__MAX
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
	struct sys	*sys;
};

/*
 * Used for regular directory page listing template.
 */
struct	dirpage {
	struct fref	*frefs; /* file references */
	size_t		 frefsz; /* all file count */
	size_t		 filesz; /* non-.. file/dir count */
	size_t		 rfilesz; /* regular file count */
	int		 rdwr; /* is read-writable? */
	int		 root; /* is document root? */
	const char	*fpath; /* request path w/script name */
	struct sys	*sys;
};

/*
 * Used for error page template.
 */
struct	errorpage {
	const char	*msg; /* error message */
	struct sys	*sys;
};

/*
 * This is the system object.
 * It's filled in for each request.
 * The descriptors are initialised to -1, but in the non-degenerative
 * case are valid.
 */
struct	sys {
	const char	*cachedir; /* root of system files */
	const char	*filedir; /* root of files */
	const char	*authdir; /* root of cookies */
	int		 cachefd; /* directory handle */
	int		 filefd; /* directory handle */
	int		 authfd; /* directory handle */
	const char	*resource; /* requested resource */
	struct kreq	 req; /* request */
	int		 loggedin; /* logged in? */
	const char	*curuser; /* if logged in (or NULL) */
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

static const char *const templs[TEMPL__MAX] = {
	"URL", /* TEMPL_URL */
	"CLASSES", /* TEMPL_CLASSES */
	"USER", /* TEMPL_USER */
	"MESSAGE", /* TEMPL_MESSAGE */
	"FILES", /* TEMPL_FILES */
};

static void
errorpage(struct sys *, const char *, ...) 
	__attribute__((format(printf, 2, 3)));

/*
 * Fill out all HTTP secure headers.
 * Use the existing document's MIME type.
 * Then emit the body indicator.
 */
static void
http_open_mime(struct kreq *r, enum khttp code, enum kmime mime)
{

	khttp_head(r, kresps[KRESP_STATUS], 
		"%s", khttps[code]);
	if (KMIME__MAX == mime)
		mime = KMIME_APP_OCTET_STREAM;
	khttp_head(r, kresps[KRESP_CONTENT_TYPE], 
		"%s", kmimetypes[mime]);
	khttp_head(r, "X-Content-Type-Options", "nosniff");
	khttp_head(r, "X-Frame-Options", "DENY");
	khttp_head(r, "X-XSS-Protection", "1; mode=block");
	khttp_body(r);
}

/*
 * See http_open_mime() with the requested document's MIME.
 */
static void
http_open(struct kreq *r, enum khttp code)
{

	http_open_mime(r, code, r->mime);
}

/*
 * Creates a zip file of the directory contents in "nfd".
 */
static char *
zip_create(struct sys *sys, int nfd)
{
	int	 	 nnfd, fd, erp;
	zip_error_t	 zer;
	char	 	 sfn[25];
	char		*ret = NULL;
	zip_t		*zip = NULL;
	DIR		*dir = NULL;
	FILE		*f;
	zip_source_t	*src;
	struct dirent	*dp;

	strlcpy(sfn, "/tmp/httpdrop.XXXXXXXXXX", sizeof(sfn));
	if (NULL == mktemp(sfn)) {
		kutil_warn(&sys->req, sys->curuser, "mktemp");
		return(NULL);
	} 

	kutil_info(&sys->req, sys->curuser, 
		"%s: filling: %s/%s", sfn,
		sys->filedir, sys->resource);

	zip = zip_open(sfn, ZIP_CREATE | ZIP_EXCL, &erp);

	if (NULL == zip) {
		zip_error_init_with_code(&zer, erp);
		kutil_warnx(&sys->req, sys->curuser,
			"%s: %s", sfn, zip_error_strerror(&zer));
		zip_error_fini(&zer);
		goto out;
	}

	/* 
	 * Iterate through regular non-dot files in nfd.
	 * We make a copy of nfd because fdopendir() will swallow the
	 * descriptor and close it on closedir().
	 */

	if (-1 == (nnfd = dup(nfd))) {
		kutil_warn(&sys->req, sys->curuser, "dup");
		goto out;
	} else if (NULL == (dir = fdopendir(nnfd))) {
		kutil_warn(&sys->req, sys->curuser, "%s/%s: "
			"fdopendir", sys->filedir, sys->resource);
		close(nnfd);
		goto out;
	}

	while (NULL != (dp = readdir(dir))) {
		if (DT_REG != dp->d_type || '.' == dp->d_name[0])
			continue;

		kutil_info(&sys->req, sys->curuser, 
			"%s: adding: %s/%s/%s", sfn,
			sys->filedir, sys->resource, dp->d_name);

		fd = openat(nfd, dp->d_name, O_RDONLY, 0);
		if (-1 == fd) {
			kutil_warn(&sys->req, sys->curuser,
				"%s/%s/%s: openat", sys->filedir, 
				sys->resource, dp->d_name);
			goto out;
		} else if (NULL == (f = fdopen(fd, "r"))) {
			kutil_warn(&sys->req, sys->curuser,
				"%s/%s/%s: fdopen", sys->filedir,
				sys->resource, dp->d_name);
			close(fd);
			goto out;
		}

		/* Open ZIP source (transfers stream ownership). */

		src = zip_source_filep_create(f, 0, -1, &zer);
		if (NULL == src) {
			kutil_warnx(&sys->req, sys->curuser, "%s: "
				"%s", sfn, zip_error_strerror(&zer));
			fclose(f);
			goto out;
		} else if (zip_file_add(zip, dp->d_name, src, 0) < 0) {
			kutil_warnx(&sys->req, sys->curuser, 
				"%s: %s", sfn, zip_strerror(zip));
			zip_source_free(src);
			goto out;
		}
	}

	/* Close directory and ZIP archive file. */

	closedir(dir);
	dir = NULL;
	if ((erp = zip_close(zip)) < 0) {
		kutil_warnx(&sys->req, sys->curuser, 
			"%s: %s", sfn, zip_strerror(zip));
		goto out;
	}
	zip = NULL;
	ret = kstrdup(sfn);
out:
	if (NULL != dir)
		closedir(dir);
	if (NULL != zip)
		zip_discard(zip);
	return(ret);
}

/*
 * Fill in templates to the login page (PAGE_LOGIN).
 */
static int
loginpage_template(size_t index, void *arg)
{
	struct loginpage *pg = arg;
	struct khtmlreq	  req;

	khtml_open(&req, &pg->sys->req, KHTML_PRETTY);

	switch (index) {
	case TEMPL_URL:
		khtml_puts(&req, pg->sys->req.fullpath);
		break;
	case TEMPL_CLASSES:
		switch (pg->error) {
		case LOGINERR_BADCREDS:
			khtml_puts(&req, "error-badcreds");
			break;
		case LOGINERR_NOFIELD:
			khtml_puts(&req, "error-nofield");
			break;
		case LOGINERR_SYSERR:
			khtml_puts(&req, "error-syserr");
			break;
		default:
			break;
		}
		break;
	default:
		khtml_close(&req);
		return(0);
	}

	khtml_close(&req);
	return(1);
}

/*
 * Login page.
 * Formats an error (or no error) depending on "error".
 * Emits HTTP 200 with the page contents.
 */
static void
loginpage(struct sys *sys, enum loginerr error)
{
	struct ktemplate t;
	struct loginpage loginpage;

	loginpage.sys = sys;
	loginpage.error = error;

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = templs;
	t.keysz = TEMPL__MAX;
	t.arg = &loginpage;
	t.cb = loginpage_template;
	http_open_mime(&sys->req, KHTTP_200, KMIME_TEXT_HTML);
	khttp_template(&sys->req, &t, DATADIR "/loginpage.xml");
}

/*
 * Fill in templates to the error page.
 */
static int
errorpage_template(size_t index, void *arg)
{
	struct errorpage *pg = arg;
	struct khtmlreq	  req;
	char		  classes[1024];

	classes[0] = '\0';
	khtml_open(&req, &pg->sys->req, KHTML_PRETTY);

	switch (index) {
	case TEMPL_URL:
		khtml_puts(&req, pg->sys->req.fullpath);
		break;
	case TEMPL_CLASSES:
		strlcat(classes, pg->sys->loggedin ?
			" loggedin" : "", sizeof(classes));
		khtml_puts(&req, classes);
		break;
	case TEMPL_USER:
		if (NULL == pg->sys->curuser)
			break;
		khtml_puts(&req, pg->sys->curuser);
		break;
	case TEMPL_MESSAGE:
		khtml_puts(&req, pg->msg);
		break;
	default:
		khtml_close(&req);
		return(0);
	}

	khtml_close(&req);
	return(1);
}

/*
 * Error page.
 * Formats an error message depending on varargs.
 * Emits HTTP 200 with the page contents.
 */
static void
errorpage(struct sys *sys, const char *fmt, ...)
{
	struct errorpage pg;
	char		*buf;
	va_list		 ap;
	struct ktemplate t;

	va_start(ap, fmt);
	if (-1 == vasprintf(&buf, fmt, ap))
		exit(EXIT_FAILURE);
	va_end(ap);

	pg.msg = buf;
	pg.sys = sys;

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = templs;
	t.keysz = TEMPL__MAX;
	t.arg = &pg;
	t.cb = errorpage_template;
	http_open_mime(&sys->req, KHTTP_200, KMIME_TEXT_HTML);
	khttp_template(&sys->req, &t, DATADIR "/errorpage.xml");
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

/*
 * Fill in templates to the directory listing page.
 */
static int
get_dir_template(size_t index, void *arg)
{
	struct dirpage	*pg = arg;
	struct khtmlreq	 req;
	struct fref	*ff;
	size_t		 i;
	char		 classes[1024];

	classes[0] = '\0';
	khtml_open(&req, &pg->sys->req, KHTML_PRETTY);

	switch (index) {
	case TEMPL_URL:
		khtml_puts(&req, pg->sys->req.fullpath);
		khtml_close(&req);
		return(1);
	case TEMPL_CLASSES:
		strlcat(classes, pg->rdwr ?
			" mutable" : " immutable", sizeof(classes));
		strlcat(classes, pg->root ?
			" root" : " nonroot", sizeof(classes));
		strlcat(classes, pg->filesz > 0 ?
			" nonempty" : " empty", sizeof(classes));
		strlcat(classes, pg->rfilesz > 0 ?
			" regnonempty" : " regempty", sizeof(classes));
		strlcat(classes, pg->sys->loggedin ?
			" loggedin" : "", sizeof(classes));
		khtml_puts(&req, classes);
		khtml_close(&req);
		return(1);
	case TEMPL_USER:
		if (NULL != pg->sys->curuser)
			khtml_puts(&req, pg->sys->curuser);
		khtml_close(&req);
		return(1);
	case TEMPL_FILES:
		break;
	default:
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
						"is-danger is-small",
					KATTR_TITLE, "Delete",
					KATTR_TYPE, "submit",
					KATTR__MAX);
			else
				khtml_attr(&req, KELEM_BUTTON,
					KATTR_CLASS, "button "
						"is-danger is-small",
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
get_dir(struct sys *sys, int rdwr)
{
	int		 nfd, nnfd;
	struct stat	 st;
	char		*fpath;
	DIR		*dir;
	struct dirent	*dp;
	int		 fl = O_RDONLY | O_DIRECTORY;
	size_t		 filesz = 0, rfilesz = 0, rffilesz = 0, i;
	struct ktemplate t;
	struct fref	*files = NULL;
	struct dirpage	 dirpage;

	if ('\0' != sys->resource[0]) {
		nfd = openat(sys->filefd, sys->resource, fl, 0);
		if (-1 == nfd)
			kutil_warn(&sys->req, sys->curuser, 
				"%s: openat", sys->resource);
	} else if (-1 == (nfd = dup(sys->filefd)))
		kutil_warn(&sys->req, sys->curuser, 
			"%s: dup", sys->resource);

	if (-1 == nfd) {
		errorpage(sys, "Cannot open \"%s\".", sys->resource);
		return;
	}

	/* 
	 * Get the DIR pointer from the directory request.
	 * We clone nfd because fdopendir() will take ownership.
	 * Then read all acceptable entries into our "files" array.
	 */

	if (-1 == (nnfd = dup(nfd))) {
		kutil_warn(&sys->req, sys->curuser, "dup");
		errorpage(sys, "System error.");
		return;
	} else if (NULL == (dir = fdopendir(nnfd))) {
		kutil_warn(&sys->req, sys->curuser, 
			"%s: fdopendir", sys->resource);
		errorpage(sys, "System error.");
		close(nnfd);
		return;
	}

	while (NULL != (dp = readdir(dir))) {
		/* 
		 * Disallow non-regular or directory, the current
		 * directory, any dot-files, and previous when in the
		 * root.
		 */

		if ((DT_DIR != dp->d_type && 
		     DT_REG != dp->d_type) ||
		    (DT_DIR == dp->d_type && 
		     0 == strcmp(dp->d_name, ".")) ||
		    (DT_REG == dp->d_type && 
		     '.' == dp->d_name[0]) ||
		    (0 == strcmp(dp->d_name, "..") &&
		    '\0' == sys->resource[0]))
			continue;

		if (-1 == fstatat(nfd, dp->d_name, &st, 0))
			continue;

		kasprintf(&fpath, "%s/%s%s%s", sys->req.pname, 
			sys->resource, 
			'\0' != sys->resource[0] ? "/" : "", 
			dp->d_name);
		files = kreallocarray(files, 
			filesz + 1, sizeof(struct fref));
		files[filesz].st = st;
		files[filesz].name = kstrdup(dp->d_name);
		files[filesz].fullname = fpath;
		filesz++;
		if (strcmp(dp->d_name, ".."))
			rfilesz++;
		if (DT_REG == dp->d_type)
			rffilesz++;
	}

	closedir(dir);

	qsort(files, filesz, sizeof(struct fref), fref_cmp);

	kasprintf(&fpath, "%s/%s%s", sys->req.pname, 
		sys->resource, '\0' != sys->resource[0] ? "/" : "");

	dirpage.frefs = files;
	dirpage.frefsz = filesz;
	dirpage.filesz = rfilesz;
	dirpage.rfilesz = rffilesz;
	dirpage.rdwr = rdwr;
	dirpage.fpath = fpath;
	dirpage.root = '\0' == sys->resource[0];
	dirpage.sys = sys;

	/*
	 * No more errors reported.
	 * Print all of our entities along with a header allowing us to
	 * upload more files.
	 */

	memset(&t, 0, sizeof(struct ktemplate));
	t.key = templs;
	t.keysz = TEMPL__MAX;
	t.arg = &dirpage;
	t.cb = get_dir_template;

	http_open(&sys->req, KHTTP_200);
	khttp_template(&sys->req, &t, DATADIR "/page.xml");

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
get_file(struct sys *sys, const struct stat *st)
{
	int		  nfd;

	if (S_ISREG(st->st_mode)) {
		errorpage(sys, "Cannot open \"%s\".", sys->resource);
		return;
	}

	nfd = openat(sys->filefd, sys->resource, O_RDONLY, 0);
	if (-1 == nfd) {
		kutil_warn(&sys->req, sys->curuser, 
			"%s: openat", sys->resource);
		errorpage(sys, "Cannot open \"%s\".", sys->resource);
		return;
	}

	/*
	 * FIXME: use last-updated with the struct state of the
	 * file and cross-check.
	 * FIXME: range headers.
	 * FIXME: KMETHOD_HEAD.
	 */

	http_open(&sys->req, KHTTP_200);
	khttp_template_fd(&sys->req, NULL, nfd, sys->resource);
	close(nfd);
}

/*
 * Send a 301 error back to the current page.
 * This is used after making a POST.
 */
static void
send_301_path(struct sys *sys, const char *fullpath)
{
	char	*np, *path;
	struct kreq	*r = &sys->req;

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
send_301(struct sys *sys)
{

	send_301_path(sys, sys->req.fullpath);
}

/*
 * Unlink a regular file "fn" relative to the current path "path" with
 * file descriptor "nfd".
 */
static void
post_op_rmfile(struct sys *sys, int nfd, const char *fn)
{

	if (-1 == unlinkat(nfd, fn, 0) && ENOENT != errno) {
		kutil_warn(&sys->req, sys->curuser, 
			"%s/%s: unlinkat", sys->resource, fn);
		errorpage(sys, "Cannot remove \"%s\".", fn);
	} else {
		kutil_info(&sys->req, sys->curuser, 
			"%s/%s: unlink", sys->resource, fn);
		send_301(sys);
	}
}

/*
 * Try to remove the current directory.
 * Send us to the directory above our own.
 */
static void
post_op_rmdir(struct sys *sys)
{
	char	*newpath, *cp;
	int	 rc;

	if ('\0' == sys->resource[0]) {
		kutil_warn(&sys->req, sys->curuser, 
			"cannot removing root");
		errorpage(sys, "You cannot remove this directory.");
		return;
	}

	rc = unlinkat(sys->filefd, sys->resource, AT_REMOVEDIR);

	if (-1 == rc && ENOENT != errno) {
		kutil_warn(&sys->req, sys->curuser, 
			"%s: unlinkat (dir)", sys->resource);
		errorpage(sys, "Cannot remove \"%s\".", sys->resource);
	} else {
		kutil_info(&sys->req, sys->curuser, 
			"%s: unlink (dir)", sys->resource);
		newpath = kstrdup(sys->resource);
		/* Strip to path above. */
		if (NULL != (cp = strrchr(newpath, '/')))
			*cp = '\0';
		else
			newpath[0] = '\0';
		send_301_path(sys, newpath);
		free(newpath);
	}
}

static void
post_op_getzip(struct sys *sys, int nfd)
{
	char		*fname, *url;
	char		 date[30];
	const char	*cp;

	kutil_epoch2utcstr(time(NULL), date, sizeof(date));

	cp = strrchr(sys->resource, '/');
	if (NULL == cp)
		cp = sys->resource;
	else
		cp++;

	kasprintf(&url, "%s.%s.zip", cp, date);

	if (NULL == (fname = zip_create(sys, nfd))) {
		errorpage(sys, "System error.");
		return;
	}

	khttp_head(&sys->req, kresps[KRESP_CONTENT_DISPOSITION], 
		"attachment; filename=\"%s\"", url);
	http_open_mime(&sys->req, KHTTP_200, KMIME_APP_OCTET_STREAM);
	khttp_template(&sys->req, NULL, fname);
	remove(fname);
	free(fname);
	free(url);
}

/*
 * Make a directory "pn" relative to the current path "path" with file
 * descriptor "nfd".
 */
static void
post_op_mkdir(struct sys *sys, int nfd, const char *pn)
{

	if (-1 == mkdirat(nfd, pn, 0700) && EEXIST != errno) {
		kutil_warn(&sys->req, sys->curuser, 
			"%s/%s: mkdirat", sys->resource, pn);
		errorpage(sys, "Cannot create \"%s\".", pn);
	} else {
		kutil_info(&sys->req, sys->curuser, 
			"%s/%s: created", sys->resource, pn);
		send_301(sys);
	}
}

/*
 * Write all files named within the "KEY_FILE" designation.
 * Use file contents "data" of size "sz".
 * FIXME: have this perform after closing the connection, else it might
 * block the connection.
 */
static void
post_op_mkfile(struct sys *sys, int nfd)
{
	int	 	 dfd, fl = O_WRONLY|O_TRUNC|O_CREAT;
	ssize_t	 	 ssz;
	struct kpair	*kp;

	for (kp = sys->req.fieldmap[KEY_FILE]; NULL != kp; kp = kp->next)
		if ('\0' == kp->file[0] ||
		    NULL != strchr(kp->file, '/') || 
		    '.' == kp->file[0]) {
			errorpage(sys, "Filename security violation.");
			return;
		}

	for (kp = sys->req.fieldmap[KEY_FILE]; NULL != kp; kp = kp->next) {
		if (-1 == (dfd = openat(nfd, kp->file, fl, 0600))) {
			kutil_warn(&sys->req, sys->curuser, 
				"%s/%s: openat", sys->resource, 
				kp->file);
			errorpage(sys, "System error.");
			return;
		}
		if ((ssz = write(dfd, kp->val, kp->valsz)) < 0) {
			kutil_warn(&sys->req, sys->curuser, 
				"%s/%s: write", sys->resource, 
				kp->file);
			errorpage(sys, "System error.");
			close(dfd);
			return;
		} else if ((size_t)ssz < kp->valsz) {
			kutil_warnx(&sys->req, sys->curuser, 
				"%s/%s: short write", 
				sys->resource, kp->file);
			errorpage(sys, "System error.");
			close(dfd);
			return;
		} else {
			kutil_info(&sys->req, sys->curuser, 
				"%s/%s: wrote %zu bytes", 
				sys->resource, kp->file, kp->valsz);
		}
		close(dfd);
	}

	send_301(sys);
}

/*
 * Process an operation to make a file or directory.
 * This routes to either post_op_mkfile or post_op_mkdir.
 */
static void
post_op_file(struct sys *sys, enum action act)
{
	int		 nfd = -1;
	int		 dfl = O_RDONLY|O_DIRECTORY;
	const char	*target;

	/* Start with validation. */

	if (ACTION_MKFILE == act &&
	    (NULL == sys->req.fieldmap[KEY_FILE] ||
	     '\0' == sys->req.fieldmap[KEY_FILE]->file[0])) {
		send_301(sys);
		return;
	} 

	if (ACTION_RMFILE == act &&
	    NULL == sys->req.fieldmap[KEY_FILENAME]) {
		send_301(sys);
		return;
	}

	if (ACTION_MKDIR == act &&
	    NULL == sys->req.fieldmap[KEY_DIR]) {
		send_301(sys);
		return;
	}

	/* What we're working with. */

	target = ACTION_RMFILE == act ?
		sys->req.fieldmap[KEY_FILENAME]->parsed.s :
		ACTION_MKDIR == act ?
		sys->req.fieldmap[KEY_DIR]->parsed.s : NULL;

	if (NULL != target &&
	    (NULL != strchr(target, '/') || '.' == target[0])) {
		errorpage(sys, "File name security violation.");
		return;
	}

	/* Open the path we're writing into. */

	if ('\0' != sys->resource[0]) {
		nfd = openat(sys->filefd, sys->resource, dfl, 0);
		if (-1 == nfd)
			kutil_warn(&sys->req, sys->curuser, 
				"%s: openat", sys->resource);
	} else if (-1 == (nfd = dup(sys->filefd)))
		kutil_warn(&sys->req, sys->curuser, 
			"%s: dup", sys->resource);

	if (-1 == nfd) {
		errorpage(sys, "Cannot open \"%s\".", sys->resource);
		goto out;
	}

	/* Now actually perform our operations. */

	if (ACTION_MKFILE == act)
		post_op_mkfile(sys, nfd);
	else if (ACTION_RMFILE == act)
		post_op_rmfile(sys, nfd, target);
	else if (ACTION_RMDIR == act)
		post_op_rmdir(sys);
	else if (ACTION_MKDIR == act)
		post_op_mkdir(sys, nfd, target);
	else if (ACTION_GETZIP == act)
		post_op_getzip(sys, nfd);
out:
	if (-1 != nfd)
		close(nfd);
}

static void
post_op_logout(struct sys *sys)
{
	const char	*secure;
	char		 buf[32];

	kutil_epoch2str(0, buf, sizeof(buf));
#ifdef SECURE
	secure = " secure;";
#else
	secure = "";
#endif
	assert(NULL != sys->curuser);
	assert(sys->loggedin);

	if (-1 == unlinkat(sys->authfd, sys->curuser, 0))
		kutil_warn(&sys->req, sys->curuser, 
			"%s/%s", sys->authdir, sys->curuser);

	khttp_head(&sys->req, kresps[KRESP_SET_COOKIE],
		"%s=; path=/;%s HttpOnly; expires=%s", 
		keys[KEY_SESSCOOKIE].name, secure, buf);
	khttp_head(&sys->req, kresps[KRESP_SET_COOKIE],
		"%s=; path=/;%s HttpOnly; expires=%s", 
		keys[KEY_SESSUSER].name, secure, buf);
	send_301_path(sys, "/");
	kutil_info(&sys->req, sys->curuser, "user logged out");
}

static void
post_op_login(struct sys *sys, const struct userq *uq)
{
	int	 	 fd;
	const char	*name, *pass, *secure;
	char		 buf[1024];
	const struct user *u;
	int64_t		 cookie;

	if (NULL == sys->req.fieldmap[KEY_USER] ||
	    NULL == sys->req.fieldmap[KEY_PASSWD]) {
		loginpage(sys, LOGINERR_NOFIELD);
		return;
	}

	/*
	 * Look up the username, make sure it exists, then check against
	 * the given hash using the crypt_checkpass function, which does
	 * the heavy lefting for us.
	 * Don't report errors: baddies could spam the log.
	 */

	name = sys->req.fieldmap[KEY_USER]->parsed.s;
	pass = sys->req.fieldmap[KEY_PASSWD]->parsed.s;

	TAILQ_FOREACH(u, uq, entries)
		if (0 == strcasecmp(u->name, name))
			break;

	if (NULL == u) {
		loginpage(sys, LOGINERR_BADCREDS);
		return;
	} else if (crypt_checkpass(pass, u->hash)) {
		loginpage(sys, LOGINERR_BADCREDS);
		return;
	}

	/*
	 * Create a random cookie (session token) and overwrite whatever
	 * is currently in our cookie file, if at all.
	 */

	cookie = arc4random();
	snprintf(buf, sizeof(buf), "%" PRId64 "\n", cookie);

	fd = openat(sys->authfd, name, 
		O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (-1 == fd) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s", sys->authdir, name);
		loginpage(sys, LOGINERR_SYSERR);
		return;
	}
	if (write(fd, buf, strlen(buf)) < 0) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s", sys->authdir, name);
		loginpage(sys, LOGINERR_SYSERR);
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
	khttp_head(&sys->req, kresps[KRESP_SET_COOKIE],
		"%s=%" PRId64 ";%s HttpOnly; path=/; expires=%s", 
		keys[KEY_SESSCOOKIE].name, cookie, secure, buf);
	khttp_head(&sys->req, kresps[KRESP_SET_COOKIE],
		"%s=%s;%s HttpOnly; path=/; expires=%s", 
		keys[KEY_SESSUSER].name, name, secure, buf);
	send_301(sys);

	kutil_info(&sys->req, name, "user logged in");
}

/*
 * Try to open the non-empty and relative directory "dir" within the
 * cache directory.
 * Return the file descriptor on success else -1.
 */
static int
open_dir(struct sys *sys, const char *dir)
{
	int	 fd, fl = O_RDONLY | O_DIRECTORY;

	if ('\0' == dir[0]) {
		kutil_warn(&sys->req, NULL, 
			"zero-length pathname");
		return(-1);
	} else if ('/' == dir[0]) {
		kutil_warn(&sys->req, NULL, 
			"%s: absolute path name", dir);
		return(-1);
	}

	fd = openat(sys->cachefd, dir, fl, 0);

	if (-1 == fd && ENOENT == errno) {
		kutil_info(&sys->req, NULL, 
			"%s/%s: creating path", 
			sys->cachedir, dir);
		if (-1 == mkdirat(sys->cachefd, dir, 0700)) {
			kutil_warn(&sys->req, NULL, 
				"%s/%s: mkdir", sys->cachedir, dir);
			return(-1);
		}
		fd = openat(sys->cachefd, dir, fl, 0);
	} else if (-1 == fd)
		kutil_warn(&sys->req, NULL, 
			"%s/%s: open", sys->cachedir, dir);

	return(fd);
}

/*
 * Try to open the file ".htpasswd" within the cache directory.
 * Return zero on fatal error, non-zero on success.
 * The "uq" field will not be allocated if the file was not found;
 * otherwise, it will be allocated and filled with a (possibly-zero)
 * user entries.
 * Note that "uq" might be allocated on failure.
 */
static int
open_users(struct sys *sys, struct userq **uq)
{
	int		 fd;
	FILE		*f;
	char		*buf;
	const char	*fn = ".htpasswd";
	size_t		 len, line = 1;
	char		*user, *pass;
	struct user	*u;

	fd = openat(sys->cachefd, fn, O_RDONLY, 0);

	if (-1 == fd && ENOENT != errno) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s: open", sys->cachedir, fn);
		return(0);
	} else if (-1 == fd) 
		return(1);

	if (NULL == (f = fdopen(fd, "r"))) {
		kutil_warn(&sys->req, NULL, 
			"%s/%s: fopen", sys->cachedir, fn);
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
		TAILQ_INSERT_TAIL(*uq, u, entries);
		line++;
	}

	fclose(f);
	return(1);
}

/*
 * Open our root directory, which must be absolute.
 * All subsequent operations will be relative to this path.
 * Returns zero on failure, non-zero on success.
 */
static int
open_cachedir(struct sys *sys)
{
	int	 fl = O_RDONLY | O_DIRECTORY;

	if ('\0' == sys->cachedir[0]) {
		kutil_warn(&sys->req, NULL, 
			"zero-length cache pathname");
		return(0);
	} else if ('/' != sys->cachedir[0]) {
		kutil_warn(&sys->req, NULL, 
			"%s: relative cache pathname", 
			sys->cachedir);
		return(0);
	}

	sys->cachefd = open(sys->cachedir, fl, 0);

	if (-1 == sys->cachefd && ENOENT == errno) {
		kutil_info(&sys->req, NULL, 
			"%s: creating cache directory", 
			sys->cachedir);
		if (-1 == mkdir(sys->cachedir, 0700)) {
			kutil_warn(&sys->req, NULL, 
				"%s: mkdir", sys->cachedir);
			return(0);
		}
		sys->cachefd = open(sys->cachedir, fl, 0);
	} else if (-1 == sys->cachefd)
		kutil_warn(&sys->req, NULL, 
			"%s: open", sys->cachedir);

	return(-1 != sys->cachefd);
}

/*
 * Look in the authdir the cookie registered to the current user (who
 * must exist) and cross-check its unique token.
 * Returns zero on failure, non-zero on success.
 */
static int
check_login(struct sys *sys, const struct userq *uq)
{
	const char	*name;
	int		 nfd;
	FILE		*f;
	int64_t		 cookie, ccookie;
	const struct user *u;

	assert(NULL != sys->req.cookiemap[KEY_SESSCOOKIE]);
	assert(NULL != sys->req.cookiemap[KEY_SESSUSER]);

	name = sys->req.cookiemap[KEY_SESSUSER]->parsed.s;
	cookie = sys->req.cookiemap[KEY_SESSCOOKIE]->parsed.i;

	/* 
	 * Loop for user in known users.
	 * If we don't find one, just exit.
	 * This prevents an attacker from spamming the log.
	 */

	TAILQ_FOREACH(u, uq, entries)
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

	if ( ! (sys->loggedin = (cookie == ccookie)))
		kutil_warn(&sys->req, name, "cookie token mismatch");
	else
		sys->curuser = name;

	fclose(f);
	return(sys->loggedin);
}

int
main(void)
{
	enum kcgi_err	 er;
	int		 rc, isw, fd;
	enum ftype	 ftype = FTYPE_DIR;
	char		*path = NULL;
	struct stat	 st;
	struct user	*u;
	struct kpair	*kp;
	enum action	 act = ACTION__MAX;
	struct userq	*uq = NULL;
	struct sys	 sys;

	memset(&sys, 0, sizeof(struct sys));

	sys.cachefd = sys.filefd = -1;
	sys.cachedir = CACHEDIR;
	sys.filedir = FILEDIR;
	sys.authdir = AUTHDIR;

	/* Log into a separate logfile (not system log). */

	kutil_openlog(LOGFILE);

	/* 
	 * Actually parse HTTP document.
	 * Then drop privileges to only have file-system access.
	 * (The pledge will further narrow based on request.)
	 */

	er = khttp_parse(&sys.req, keys, 
		KEY__MAX, pages, PAGE__MAX, PAGE_INDEX);

	if (KCGI_OK != er) {
		fprintf(stderr, "HTTP parse error: %d\n", er);
		return(EXIT_FAILURE);
	}

	if (-1 == pledge("fattr rpath cpath wpath stdio", NULL)) {
		kutil_warn(&sys.req, NULL, "pledge");
		goto out;
	}

	/*
	 * Front line of defence: make sure we're a proper method and
	 * make sure we're an HTML file.
	 */

	if (KMETHOD_GET != sys.req.method && 
	    KMETHOD_POST != sys.req.method) {
		errorpage(&sys, "Invalid HTTP method.");
		goto out;
	}

	/* 
	 * Security: don't let us request a relative path.
	 * Then force to be relative and strip trailing slashes.
	 */

	if (NULL != strstr(sys.req.fullpath, "/..") ||
	    ('\0' != sys.req.fullpath[0] && '/' != sys.req.fullpath[0])) {
		errorpage(&sys, "Security violation in requested path.");
		goto out;
	} 

	path = kstrdup(sys.req.fullpath);
	if ('\0' != path[0] && '/' == path[strlen(path) - 1])
		path[strlen(path) - 1] = '\0';
	sys.resource = path;
	if ('/' == sys.resource[0])
		sys.resource++;

	/* Open files/directories: cache, cookies, files. */

	if ( ! open_cachedir(&sys)) {
		errorpage(&sys, "Cannot open cache root.");
		goto out;
	}

	if ( ! open_users(&sys, &uq)) {
		errorpage(&sys, "Cannot process password file.");
		goto out;
	}

	if (-1 == (fd = open_dir(&sys, sys.filedir))) {
		errorpage(&sys, "Cannot open file root.");
		goto out;
	}
	sys.filefd = fd;

	if (-1 == (fd = open_dir(&sys, sys.authdir))) {
		errorpage(&sys, "Cannot open authorisation root.");
		goto out;
	}
	sys.authfd = fd;

	/* 
	 * Now figure out what we're supposed to do here.
	 * This will sanitise our request action.
	 * Then switch on those actions.
	 */

	if (KMETHOD_GET != sys.req.method) {
		if (NULL == (kp = sys.req.fieldmap[KEY_OP])) 
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
		else if (0 == strcmp(kp->parsed.s, "getzip"))
			act = ACTION_GETZIP;
	} else
		act = ACTION_GET;

	if (ACTION__MAX == act) {
		errorpage(&sys, "Unspecified operation.");
		goto out;
	}

	/* Getting (readonly): drop privileges. */

	if (ACTION_GET == act)
		if (-1 == pledge("rpath stdio", NULL)) {
			kutil_warn(&sys.req, NULL, "pledge");
			errorpage(&sys, "System error.");
			goto out;
		}

	/* Logging in: jump straight to login page. */

	if (ACTION_LOGIN == act) {
		post_op_login(&sys, uq);
		goto out;
	}

	/*
	 * We know what we want to do, but not whether we can.
	 * If we have users, check for session availability.
	 * If we don't have a session, or the session is a bad one, then
	 * kick us to the login page.
	 */

	if (NULL != uq)
		if (NULL == sys.req.cookiemap[KEY_SESSCOOKIE] ||
		    NULL == sys.req.cookiemap[KEY_SESSUSER] ||
		    ! check_login(&sys, uq)) {
			loginpage(&sys, LOGINERR_OK);
			goto out;
		}

	/* Logout only after session is validated. */

	if (ACTION_LOGOUT == act && sys.loggedin) {
		post_op_logout(&sys);
		goto out;
	} else if (ACTION_LOGOUT == act) {
		send_301_path(&sys, "/");
		goto out;
	}

	/*
	 * See what kind of resource we're asking for by looking it up
	 * under the cache root.
	 * Disallow non-regular or directory files.
	 */

	rc = '\0' != sys.resource[0] ? 
		fstatat(sys.filefd, sys.resource, &st, 0) : 
		fstat(sys.filefd, &st);

	if (-1 == rc) {
		errorpage(&sys, "Resource not found or unavailable.");
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
		kutil_warn(&sys.req, NULL, "getgroups");
		errorpage(&sys, "System error.");
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
			get_dir(&sys, isw);
		else
			get_file(&sys, &st);
	} else {
		if (FTYPE_DIR != ftype)
			errorpage(&sys, "Post into a regular file.");
		else if ( ! isw && ACTION_GETZIP != act)
			errorpage(&sys, "Post into readonly directory.");
		else
			post_op_file(&sys, act);
	}

out:
	/* Drop privileges and free memory. */

	if (-1 == pledge("stdio", NULL))
		kutil_warn(&sys.req, NULL, "pledge");

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
	if (-1 != sys.cachefd)
		close(sys.cachefd);
	if (-1 != sys.filefd)
		close(sys.filefd);
	if (-1 != sys.authfd)
		close(sys.authfd);
	khttp_free(&sys.req);
	return(EXIT_SUCCESS);
}
