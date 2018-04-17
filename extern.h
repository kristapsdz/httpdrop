#ifndef EXTERN_H
#define EXTERN_H

/* Base directory of all files. */

#ifndef	CACHEDIR
# define CACHEDIR "/cache/httpdrop"
#endif

/* Directories within the CACHEDIR. */

#define FILEDIR CACHEDIR "/files"
#define AUTHDIR CACHEDIR "/cookies"

/* Temporary directory. */

#ifndef	TMPDIR
# define TMPDIR "/tmp"
#endif

/*
 * This is the system object.
 * It's filled in for each request.
 * The descriptors are initialised to -1, but in the non-degenerative
 * case are valid.
 */
struct	sys {
	int		 filefd; /* directory handle */
	int		 authfd; /* directory handle */
	int		 tmpfd; /* directory handle */
	const char	*resource; /* requested resource */
	struct kreq	 req; /* request */
	int		 loggedin; /* logged in? */
	const char	*curuser; /* if logged in (or NULL) */
	int64_t		 curcookie; /* user cookie (if logged in) */
};

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

__BEGIN_DECLS

struct auth	*auth_file_alloc(void);
void		 auth_file_free(struct auth *);
int		 auth_file_init(const struct sys *, struct auth *);
void		 auth_file_logout(const struct sys *, struct auth *);
int		 auth_file_check(const struct sys *, const struct auth *, 
			const char *, int64_t);
int		 auth_file_chpass(const struct sys *, 
			const char *, const char *);
int64_t		 auth_file_login(const struct sys *, const struct auth *,
			const char *, const char *);

__END_DECLS

#endif /* ! EXTERN_H */
