#!/usr/bin/python

import subprocess, time
import select

class Netcat:
    nc = None
    def __init__(self):
        raise NotImplementedError
    
    def send(self,data):
        self.nc.stdin.write(data)
        time.sleep(1)

    def receive(self):
        (res,t1,t2) = select.select([self.nc.stdout],[],[],5)
        if res != [self.nc.stdout]:
            return None
        else:
            return self.nc.stdout.readline()

    def stop(self):
        if self.nc.poll() ==  None:
	        self.nc.terminate()
        self.nc.wait()

class ServerNetcat(Netcat):
    def __init__(self, port):
        self.nc = subprocess.Popen(["/bin/netcat","-l","-p","%s" % port], stdout=subprocess.PIPE)

class ClientNetcat(Netcat):
    def __init__(self, host, port):
        self.nc = subprocess.Popen(["/bin/netcat",host,"%s" % port],stdin=subprocess.PIPE)

daemon = subprocess.Popen(["../src/phoenix","-f","test.conf","-l","-v","3"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(0.2)
print daemon.pid
server = ServerNetcat(5000)
client = ClientNetcat("localhost", 5000)
client.send("kakukk\n")
#time.sleep(5)
print server.receive()
client.stop()
server.stop()
print daemon.poll()
daemon.terminate()
daemon.wait()
