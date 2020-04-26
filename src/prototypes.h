int __libc_start_main(int *(main) (int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end));
typeof(__libc_start_main) *o_libc_start_main;

/* EXEC */
int execve(const char *filename, char *const argv[], char *const envp[]);
int execvp(const char *filename, char *const argv[]);
typeof(execve) *o_execve;
typeof(execvp) *o_execvp;

/* STAT */
int stat(const char *pathname, struct stat *buf);
int stat64(const char *pathname, struct stat64 *buf);
int fstat(int fd, struct stat *buf);
int fstat64(int fd, struct stat64 *buf);
int lstat(const char *pathname, struct stat *buf);
int lstat64(const char *pathname, struct stat64 *buf);
int __xstat(int version, const char *pathname, struct stat *buf);
int __xstat64(int version, const char *pathname, struct stat64 *buf);
int __fxstat(int ver, int fd, struct stat *buf);
int __fxstat64(int ver, int fd, struct stat64 *buf);
int __lxstat(int version, const char *pathname, struct stat *buf);
int __lxstat64(int version, const char *pathname, struct stat64 *buf);
typeof(stat) *o_stat;
typeof(stat64) *o_stat64;
typeof(fstat) *o_fstat;
typeof(fstat64) *o_fstat64;
typeof(lstat) *o_lstat;
typeof(lstat64) *o_lstat64;
typeof(__xstat) *o_xstat;
typeof(__xstat64) *o_xstat64;
typeof(__fxstat) *o_fxstat;
typeof(__fxstat64) *o_fxstat64;
typeof(__lxstat) *o_lxstat;
typeof(__lxstat64) *o_lxstat64;


/* DIRECTORIES */
int rmdir(const char *pathname);
DIR *opendir(const char *name);
DIR *opendir64(const char *name);
DIR *fdopendir(int fd);
int chdir(const char *path);
int fchdir(int fd);
struct dirent *readdir(DIR *dirp);
struct dirent64 *readdir64(DIR *dirp);
typeof(rmdir) *o_rmdir;
typeof(opendir) *o_opendir;
typeof(opendir64) *o_opendir64;
typeof(fdopendir) *o_fdopendir;
typeof(readdir) *o_readdir;
typeof(readdir64) *o_readdir64;
typeof(chdir) *o_chdir;
typeof(fchdir) *o_fchdir;


/* FILE (UN)LINKING */
int link(const char *oldpath, const char *newpath);
int linkat(int oldfirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int unlink(const char *pathname);
int unlinkat(int dirfd, const char *pathname, int flags);
int symlink(const char *target, const char *linkat);
int symlinkat(const char *target, int newdirfd, const char *linkat);
typeof(link) *o_link;
typeof(linkat) *o_linkat;
typeof(unlink) *o_unlink;
typeof(unlinkat) *o_unlinkat;
typeof(symlink) *o_symlink;
typeof(symlinkat) *o_symlinkat;


/* FILE ACCESS */
int access(const char *path, int amode);
int open(const char *pathname, int flags, mode_t mode);
int open64(const char *pathname, int flags, mode_t mode);
FILE *popen(const char *command, const char *type);
FILE *fopen(const char *path, const char *mode);
FILE *fopen64(const char *path, const char *mode);
typeof(access) *o_access;
typeof(open) *o_open;
typeof(open64) *o_open64;
typeof(popen) *o_popen;
typeof(fopen) *o_fopen;
typeof(fopen64) *o_fopen64;


/* RENAMING */
int rename(const char *oldpath, const char *newpath);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
typeof(rename) *o_rename;
typeof(renameat) *o_renameat;
typeof(renameat2) *o_renameat2;


/* FILE ATTRIBUTES & PERMISSIONS */
int chmod(const char *path, mode_t mode);
int chown(const char *path, uid_t owner, gid_t group);
int fchmod(int fd, mode_t mode);
int fchown(int fd, uid_t owner, gid_t group);
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
int lchown(const char *path, uid_t owner, gid_t group);
typeof(chmod) *o_chmod;
typeof(chown) *o_chown;
typeof(fchmod) *o_fchmod;
typeof(fchown) *o_fchown;
typeof(fchownat) *o_fchownat;
typeof(lchown) *o_lchown;

ssize_t write(int fd, const void *buf, size_t count);
typeof(write) *o_write;

int socket(int domain, int type, int protocol);
typeof(socket) *o_socket;  /* sorcket breaker! */