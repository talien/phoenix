#!/usr/bin/python
#
# Copyright (c) 2008-2014 Viktor Tusa
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
#

import subprocess, time
import select, os, sys
import unittest, re

phoenixd_path = os.environ['PHOENIXD_PATH']

def get_dir_of_current_file():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def get_phoenix_path():
    return phoenixd_path + "/phoenixd"

def get_stub_client_path():
    return get_dir_of_current_file() + "/testclient.py"

class ProcessException(Exception):
    pass

class Process(object):
    process = None
    def __init__(self, args):
        try:
          self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
        except:
          raise ProcessException("Failed to start process %s" % args[0])
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

    def register_process(self, name, process):
        if not hasattr(self, "processes"):
           self.processes = {}

        self.processes[name] = process

    def stop_process(self, process):
        if process:
           process.stop()

    def stop_processes(self):
        if not hasattr(self, "processes"):
           return

        for process in self.processes.values():
           process.stop()

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
        self.register_process('daemon', self.start_phoenix("test.conf"))
        time.sleep(0.5)
        self.assertEqual(self.processes['daemon'].process.poll(), None)
        self.assertTrue(os.path.exists("test.log"))
        self.assertTrue(self.file_has_content("test.log","phoenix firewall starting up"))
    
    def tearDown(self):
        self.stop_processes()

class PhoenixAskGuiTest(unittest.TestCase,PhoenixTestMixin):

    def setUp(self):
        self.config = PhoenixConfig("test.conf",[Zone([("internet","0.0.0.0/0")]),\
                                                 Rule([("program","/bin/nc.traditional"),("direction","in"),("verdict","accept")])])

        self.config.write()

    def ask_gui_test_skeleton(self, verdict, expected):
        self.register_process('daemon', self.start_phoenix("test.conf"))
        self.register_process('gui', Process([get_stub_client_path(), "-v",verdict]))
        self.register_process('server', ServerNetcat(5000))
        self.register_process('client', ClientNetcat("localhost", 5000))
        self.processes['client'].send("kakukk\n")
        res = self.processes['server'].receive()
        self.assertEqual(res, expected)
        self.assertEqual(self.processes['daemon'].process.poll(),None)

    def test_ask_gui_allow_conn(self):
        self.ask_gui_test_skeleton("1","kakukk\n")
        
    def test_ask_gui_deny_conn(self):
        self.ask_gui_test_skeleton("2",None)
    
    def tearDown(self):
        self.stop_processes()
        self.config.remove()

class PhoenixConnTest(unittest.TestCase,PhoenixTestMixin):

    def setUp(self):
        self.reset_iptables()
 
    def make_test(self, config, expected):
        self.create_config(config)
        self.register_process('daemon', self.start_phoenix("test.conf"))
        self.register_process('server', ServerNetcat(5000))
        self.register_process('client', ClientNetcat("localhost", 5000))
        self.processes['client'].send("kakukk\n")
        res = self.processes['server'].receive()
        self.assertEqual(res, expected)
        self.assertEqual(self.processes['daemon'].process.poll(),None)
        self.stop_processes()

    def test_only_out_direction_should_fail(self):
        self.make_test("[zones]\ninternet = 0.0.0.0/0\n[rule]\nprogram = /bin/nc.traditional\nverdict = accept\ndirection = out\n",None)

    def test_in_and_out_direction_should_pass(self):
        self.make_test("[zones]\ninternet = 0.0.0.0/0\n[rule]\nprogram = /bin/nc.traditional\nverdict = accept\ndirection = out\n[rule]\nprogram = /bin/nc.traditional\nverdict = accept\ndirection = in\n","kakukk\n")

    def tearDown(self):
        self.stop_processes()

if __name__ == "__main__":
    unittest.main()
