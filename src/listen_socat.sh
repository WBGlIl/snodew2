#!/bin/bash
USAGE="
this script listens for a connection on your specified
secret port, with socat, duh. you might not be able to ^C
after you start listening. only way to stop socat (afaik)
from listening is just killing the process. just fyi.

  usage: $0 <option(s)> <port>
      options:
          -ssl:    use your generated ssl cert to listen for a connection on <port>.
                   you should have already run ssl/gencert.sh.
          -plain:  listen for a connection on <port>.

"
[ -z $1 ] && { echo "$USAGE"; exit; }
option="$1"
[ -z $2 ] && { echo "$USAGE"; exit; }
port="$2"
if [ "$option" == "-ssl" ]; then
    [ ! -f ./ssl/server.pem ] && { echo "./ssl/server.pem doesn't exist. have you used ssl/gencert.sh?"; exit; }
    [ ! -f ./ssl/client.crt ] && { echo "./ssl/client.crt doesn't exist. have you used ssl/gencert.sh?"; exit; }
    echo -e "listening on port \e[32m$port\e[0m & using ssl"
    socat file:`tty`,raw,echo=0 openssl-listen:$port,reuseaddr,cert=./ssl/server.pem,cafile=./ssl/client.crt,verify=0
elif [ "$option" == "-plain" ]; then
    echo -e "listening on port \e[32m$port\e[0m"
    socat file:`tty`,raw,echo=0 tcp-listen:$port
else echo "$USAGE"; exit; fi