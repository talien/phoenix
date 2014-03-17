#!/usr/bin/python

import subprocess, time
import select, os, sys
import unittest, re

def get_dir_of_current_file():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def get_phoenix_path():
    return get_dir_of_current_file() + "/../src/phoenixd"

def get_stub_client_path():
    return get_dir_of_current_file() + "/testclient.py"

class Process(object):
    process = None
    def __init__(self, args):
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
        msg = "Process created, pid='%s', args='%r'" % (self.process.pid, args)
        os.system("logger \"%s\"" % msg ) 
        print msg
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
           print "Send failed: Process does not exists, pid=%s" % self.process.pid
        time.sleep(0.2)

    def receive(self):
        (res,t1,t2) = select.select([self.process.stdout],[],[],5)
        if res != [self.process.stdout]:
            return None
        else:
            return self.process.stdout.readline()

   
class ServerNetcat(Netcat):
    def __init__(self, port):
        super(ServerNetcat, self).__init__(["/bin/netcat","-l","-vv","-p","%s" % port])

class ClientNetcat(Netcat):
    def __init__(self, host, port):
        super(ClientNetcat, self).__init__(["/bin/netcat",host,"%s" % port])

class PhxConfigItem:
    section_name = ""
    def __init__(self,values):
        self.values = values

    def generate(self):
        result = "[%s]\n" % self.section_name
        for value in self.values:
            result += "%s = %s\n" % (value[0], value[1])
        return result


class Zone(PhxConfigItem):
    section_name = "zones"

class Rule(PhxConfigItem):
    section_name = "rule"

class PhoenixConfig:
    def __init__(self, filename, sections):
        self.sections = sections
        self.filename = filename

    def generate(self):
        result = ""
        for section in self.sections:
            result += section.generate()
        return result

    def write(self):
        self.remove()
        conf = open(self.filename,"w")
        conf.write(self.generate())
        conf.close()

    def remove(self):
        try:
            os.unlink(self.filename)
        except:
            pass
       

class PhoenixTestMixin:
    def start_phoenix(self, config_file):
        return Process([get_phoenix_path(),"-F","test.log","-v","9","-f","test.conf"])

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

    def reset_iptables(self):
        os.system("iptables -F")
        os.system("iptables -X")

class PhoenixLogTest(unittest.TestCase,PhoenixTestMixin):
    def setUp(self):
        self.config = PhoenixConfig("test.conf",[Zone([("internet","0.0.0.0/0")])])
        self.config.write()
        self.reset_iptables()
        
    def test_create_log_file(self):
        try:
            os.unlink("test.log")
        except:
            pass
        self.daemon = self.start_phoenix("test.conf")
        time.sleep(0.5)
        self.assertEqual(self.daemon.process.poll(), None)
        self.assertTrue(os.path.exists("test.log"))
        self.assertTrue(self.file_has_content("test.log","phoenix firewall starting up"))
        self.daemon.stop()
    
    def tearDown(self):
        self.daemon.stop()

class PhoenixAskGuiTest(unittest.TestCase,PhoenixTestMixin):

    def stop_processes(self):
        self.client.stop()
        self.server.stop()
        self.daemon.stop()
        self.gui.stop()

    def ask_gui_test_skeleton(self, verdict, expected):
        self.config = PhoenixConfig("test.conf",[Zone([("internet","0.0.0.0/0")]),\
                                                 Rule([("program","/bin/nc.traditional"),("direction","in"),("verdict","accept")])])

        self.config.write()
        self.daemon = self.start_phoenix("test.conf")
        self.gui = Process([get_stub_client_path(), "-v",verdict])
        self.server = ServerNetcat(5000)
        self.client = ClientNetcat("localhost", 5000)
        self.client.send("kakukk\n")
        res = self.server.receive()
        self.assertEqual(res, expected)
        self.assertEqual(self.daemon.process.poll(),None)
        self.stop_processes()

    def test_ask_gui_allow_conn(self):
        self.ask_gui_test_skeleton("1","kakukk\n")
        
    def test_ask_gui_deny_conn(self):
        self.ask_gui_test_skeleton("2",None)
    
    def tearDown(self):
        self.stop_processes()
        self.config.remove()

class PhoenixConnTest(unittest.TestCase,PhoenixTestMixin):
    def stop_processes(self):
        self.client.stop()
        self.server.stop()
        self.daemon.stop()

    def setUp(self):
        self.reset_iptables()
 
    def make_test(self, config, expected):
        self.create_config(config)
        self.daemon = self.start_phoenix("test.conf")
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
