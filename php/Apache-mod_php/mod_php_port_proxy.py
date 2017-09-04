#!/usr/bin/env python
#coding=utf-8
# Author: wofeiwo@80sec.com
# Version: 1.0
# Last modified: 2011-09-30

import socket
import threading
import SocketServer
import urlparse
import os, sys, getopt, signal

HELP_MESSAGE        = """
pp.py [-l|--local local_addr] <remote_url> <forward_addr>
Example:
\t pp.py -l 127.0.0.1:1234 http://target.com/t.php 10.1.1.10:80
"""
verbose             = False
local_addr          = "127.0.0.1:1234"
url                 = ""
target              = ""
lserver             = None


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

class recvHandler(threading.Thread):
    def __init__(self, remote, local):
        threading.Thread.__init__(self)
        self.remote = remote
        self.local = local
    def run(self):
        while True:
            try:
                dataReceived = self.remote.recv(1024);
                if not dataReceived: break
                self.local.send(dataReceived)
            except socket.timeout:
               break
        self.remote.close()
        self.local.close()

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        global url, target

        u = urlparse.urlparse(url)
        if u.netloc.find(":") != -1:
            hostname, port    = u.netloc.split(":")
            port              = int(port)
        else:
            hostname    = u.netloc
            port        = 80

        rhost, rport = target.split(":")

        self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote.connect((hostname, port))
        self.remote.send(b"GET %s?rhost=%s&rport=%s HTTP/1.1\r\nHost: %s\r\n\r\n" % (u.path, rhost, rport, u.netloc))

        recvHandler(self.remote, self.request).start()

        while True:
            try:
                dataReceived = self.request.recv(1024)
                if not dataReceived: break
                self.remote.send(dataReceived)
            except socket.timeout:
                break

    def finish(self):
        self.request.close()
        self.remote.close()
        

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

def sigint_handler(signal, frame):
    lserver.shutdown()
    sys.exit(1)

def main(argv=None):
    global verbose, url, target, local_addr, HELP_MESSAGE, lserver
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(
                argv[1:], 
                "hl:v", 
                ["help", "local=", "verbose"]
            )
        except getopt.error, msg:
            raise Usage(msg)

        # option processing
        for option, value in opts:
            if option == "-v":
                verbose = True
            if option in ("-h", "--help"):
                raise Usage(HELP_MESSAGE)
            if option in ("-l", "--local"):
                local_addr = value
        
        if (not args) and (len(args) != 2):
            raise Usage("参数数目不够.")
        else:
            url     = args[0]
            target  = args[1]

        LHOST, LPORT = local_addr.split(":")

    except Usage, err:
        print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
        print >> sys.stderr, "[*] 获取帮助请用 -h 或 --help"
        return -1

    signal.signal(signal.SIGINT, sigint_handler)

    lserver = ThreadedTCPServer((LHOST, int(LPORT)), ThreadedTCPRequestHandler)
    lserver_thread = threading.Thread(target=lserver.serve_forever)
    # lserver_thread.setDaemon(True)
    lserver_thread.start()

if __name__ == "__main__":
    sys.exit(main())