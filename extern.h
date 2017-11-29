#ifndef EXTERN_H
#define EXTERN_H

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
	const char	*tmpdir; /* root of tmpfiles */
	int		 cachefd; /* directory handle */
	int		 filefd; /* directory handle */
	int		 authfd; /* directory handle */
	int		 tmpfd; /* directory handle */
	const char	*resource; /* requested resource */
	struct kreq	 req; /* request */
	int		 loggedin; /* logged in? */
	const char	*curuser; /* if logged in (or NULL) */
};

typedef	void *(*auth_alloc)(void);
typedef	int (*auth_init)(const struct sys *, void *);
typedef	void (*auth_logout)(const struct sys *, void *);
typedef	void (*auth_free)(void *);
typedef int (*auth_check)(const struct sys *, void *,
	const char *, int64_t); 
typedef int64_t (*auth_login)(const struct sys *, void *,
	const char *, const char *); 
typedef int (*auth_enabled)(void *);

struct	backend {
	auth_alloc	 auth_alloc;
	auth_init	 auth_init;
	auth_free	 auth_free;
	auth_check	 auth_check;
	auth_login	 auth_login;
	auth_logout	 auth_logout;
	auth_enabled	 auth_enabled;
};

__BEGIN_DECLS

void	*auth_file_alloc(void);
void	 auth_file_free(void *);
int	 auth_file_init(const struct sys *, void *);
void	 auth_file_logout(const struct sys *, void *);
int	 auth_file_check(const struct sys *, void *, 
		const char *, int64_t);
int64_t	 auth_file_login(const struct sys *, void *,
		const char *, const char *);
int	 auth_file_enabled(void *);

__END_DECLS

#endif /*!EXTERN_H*/
