#!/usr/bin/python
import socket
import os,sys
import getpass, struct

sys.path += [os.path.dirname(os.path.realpath(sys.argv[0])) + "/../scripts/"]
from phxlib import *
from optparse import OptionParser

def main():	
    op = OptionParser()
    op.add_option("-v","--verdict",dest ="verdict", metavar="VERDICT",type="int", default=0)
    (options, args) = op.parse_args()
    verdict = options.verdict
    sock_name = "/tmp/phxsock-" + getpass.getuser()
    if (os.path.exists(sock_name)):
        os.unlink(sock_name)
    listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listen_sock.bind(sock_name)
    listen_sock.listen(5)
    (newsock,tmp) = listen_sock.accept()
    print "Connection accepted"
    data = newsock.recv(4096)
    print "data: %r" % data
    a = phx_client_unpack("SI4sI4sIIIISSS",data)
    print "Unpack result:", a
    (bytes_count, (process_name, pid, srcip, sport, destip, dport, direction, srczone, destzone, sz_name, dz_name, cmd_line)) = a
    #    verdict = 1 # ACCEPTED
    #    verdict = 2 # DENIED
    if verdict == 0:
        verdict = 1
    send_data =struct.pack("<IIII", verdict, srczone, destzone, pid);
    print "Sendind data"
    newsock.send(send_data)
    newsock.close()
    listen_sock.close()

main()
