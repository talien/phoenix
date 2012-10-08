#!/usr/bin/python

import subprocess, time
import select, os
import unittest, re

class Process(object):
    process = None
    def __init__(self, args):
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
        print "Process created, pid='%s', args='%r'" % (self.process.pid, args)
        time.sleep(0.2)

    def stop(self):
        if self.process.poll() ==  None:
	        self.process.terminate()
        self.process.wait()

class Netcat(Process):
    
    def send(self,data):
        if self.process.poll() == None:
            self.process.stdin.write(data)
        else:
           print "Process does not exists, pid=%s" % self.process.pid
        time.sleep(0.2)

    def receive(self):
        (res,t1,t2) = select.select([self.process.stdout],[],[],5)
        if res != [self.process.stdout]:
            return None
        else:
            return self.process.stdout.readline()

   
class ServerNetcat(Netcat):
    def __init__(self, port):
        super(ServerNetcat, self).__init__(["/bin/netcat","-l","-p","%s" % port])

class ClientNetcat(Netcat):
    def __init__(self, host, port):
        super(ClientNetcat, self).__init__(["/bin/netcat",host,"%s" % port])

class PhoenixTestMixin:
    def create_config(self, data):
        try:
            os.unlink("test.conf")
        except:
            pass
        conf = open("test.conf","w")
        conf.write(data)
        conf.close()

    def file_has_content(self, file_name, content):
        f = open(file_name,"r")
        for line in f:
            if re.search(content, line) != None:
                return True
        return False

class PhoenixLogTest(unittest.TestCase,PhoenixTestMixin):
    def test_create_log_file(self):
        os.unlink("test.log")
        self.create_config("[zones]\ninternet = 0.0.0.0/0\n")
        daemon = Process(["../src/phoenix","-F","test.log","-v","9","-f","test.conf"])
        time.sleep(1)
        self.assertEqual(daemon.process.poll(), None)
        self.assertTrue(os.path.exists("test.log"))
        self.assertTrue(self.file_has_content("test.log","phoenix firewall starting up"))
        daemon.stop()

class PhoenixConnTest(unittest.TestCase,PhoenixTestMixin):
    def stop_processes(self):
        self.client.stop()
        self.server.stop()
        self.daemon.stop()

    def setUp(self):
        os.system("iptables -F")
        os.system("iptables -X")
 
    def make_test(self, config, expected):
        self.create_config(config)
        self.daemon = Process(["../src/phoenix","-f","test.conf","-l","-v","9"])
        print self.daemon.process.pid
        self.server = ServerNetcat(5000)
        self.client = ClientNetcat("localhost", 5000)
        self.client.send("kakukk\n")
        res = self.server.receive()
        self.assertEqual(res, expected)
        self.assertEqual(self.daemon.process.poll(),None)
        self.stop_processes()

    def test_only_out_direction_should_fail(self):
        self.make_test("[zones]\ninternet = 0.0.0.0/0\n[rule]\nprogram = /bin/nc.traditional\nverdict = accept\ndirection = out\n",None)

    def test_in_and_out_direction_should_pass(self):
        self.make_test("[zones]\ninternet = 0.0.0.0/0\n[rule]\nprogram = /bin/nc.traditional\nverdict = accept\ndirection = out\n[rule]\nprogram = /bin/nc.traditional\nverdict = accept\ndirection = in\n","kakukk\n")

    def tearDown(self):
        self.stop_processes()

if __name__ == "__main__":
    unittest.main()
