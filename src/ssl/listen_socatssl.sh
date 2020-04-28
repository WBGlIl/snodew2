#!/bin/bash
[ -z $1 ] && { echo "usage: $0 <secret port>"; exit; }
[ ! -f ./server.pem ] && { echo "./server.pem doesn't exist. have you used gencert.sh?"; exit; }
[ ! -f ./client.crt ] && { echo "./client.crt doesn't exist. have you used gencert.sh?"; exit; }
printf "listening on port $1 with socat (ssl)\n"
socat file:`tty`,raw,echo=0 openssl-listen:$1,reuseaddr,cert=./server.pem,cafile=./client.crt,verify=0