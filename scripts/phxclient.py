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

import gtk, gobject, glib
import os,sys,socket, getpass, struct
from phxlib import *

dir_map = { 0 : "Outbound", 1 : "Inbound" }

class ClientWindow(gtk.Dialog):
	def __init__(self, process_name, pid, srcip, sport, destip, dport, direction, sz_name, dz_name, src_zone, dest_zone, cmd_line):
		gtk.Dialog.__init__(self)
		self.process_name = process_name;
		self.pid = pid
		self.sz_id = sz_name;
		self.dz_id = dz_name;
		
		source_ip = "%d.%d.%d.%d" % (ord(srcip[0]), ord(srcip[1]), ord(srcip[2]), ord(srcip[3]) )
		dest_ip = "%d.%d.%d.%d" % (ord(destip[0]), ord(destip[1]), ord(destip[2]), ord(destip[3]) )
		try:
			source_dns_name = socket.gethostbyaddr(source_ip)[0];
		except:
			source_dns_name = source_ip
		try:
			dest_dns_name = socket.gethostbyaddr(dest_ip)[0];
		except:
			dest_dns_name = dest_ip
		layout = gtk.Fixed()
		layout.put(gtk.Label("The program %s with the following parameters want to reach the internet:" % process_name),10,10);
		layout.put(gtk.Label("Process ID:%d (%s)" % (pid,cmd_line)),10,35);
		layout.put(gtk.Label("Source IP: %s (%s)" % (source_ip,source_dns_name)),10,60)
		layout.put(gtk.Label("Source port: %d" % sport ),10,85)
		layout.put(gtk.Label("Destination IP: %s (%s)" % (dest_ip, dest_dns_name)),10,110)
		layout.put(gtk.Label("Destination port: %d" % dport ),10,135)
		layout.put(gtk.Label("Source zone: %s" % src_zone), 10, 160)
		layout.put(gtk.Label("Destination zone: %s" % dest_zone), 10,185)
		layout.put(gtk.Label("Direction: %s" % dir_map[direction]), 10, 210)

		self.instance_radio = gtk.RadioButton(None, "Apply for this instance")
		layout.put(self.instance_radio, 50, 235);
		layout.put(gtk.RadioButton(self.instance_radio, "Apply for all instance"),50,255)

		self.source_radio = gtk.RadioButton(None, "Apply for this source zone: %s" % src_zone)
		layout.put(self.source_radio, 50, 285);
		layout.put(gtk.RadioButton(self.source_radio, "Apply for all source zone"),50,305)

		self.destination_radio = gtk.RadioButton(None, "Apply for this destination zone: %s" % dest_zone)
		layout.put(self.destination_radio, 50, 335);
		layout.put(gtk.RadioButton(self.destination_radio, "Apply for all destination zone"),50,355)

		self.add_buttons("Accept", gtk.RESPONSE_YES, "Deny", gtk.RESPONSE_NO);

		self.vbox.pack_start(layout)
		self.show_all()

	def calculate_values(self):
		pid = self.pid
		sz = self.sz_id
		dz = self.dz_id
		if (not self.instance_radio.get_active()):
			pid = 0
		if (not self.source_radio.get_active()):
			sz = 0
		if (not self.destination_radio.get_active()):
			dz = 0

		return (pid, sz, dz)

def process_data(data):
	(bytes_num, (process_name, pid, srcip, sport, destip, dport, direction, srczone, destzone, sz_name, dz_name, cmd_line)) = phx_client_unpack("SI4sI4sIIIISSS",data)
	dialog = ClientWindow(process_name, pid, srcip, sport, destip, dport, direction, srczone, destzone, sz_name, dz_name, cmd_line)
	resp = dialog.run()
	if (resp == gtk.RESPONSE_YES):
		verdict = 1 # ACCEPTED
	else:
		verdict = 2 # DENIED
	(pid, srczone, destzone) = dialog.calculate_values()
	dialog.destroy()
	return struct.pack("<IIII", verdict, srczone, destzone, pid);
	
def gui_callback(source,condition,lsock):
	(newsock,tmp) = lsock.accept()
	data = newsock.recv(4096)
	send_data = process_data(data)
	newsock.send(send_data)
	newsock.close()
	return True

def setup_socket():
	sock_name = "/tmp/phxsock-" + getpass.getuser()
	if (os.path.exists(sock_name)):
		os.unlink(sock_name)
	listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	listen_sock.bind(sock_name)
	listen_sock.listen(5)
	return listen_sock

def main():
	listen_sock = setup_socket()
	glib.io_add_watch(listen_sock.fileno(), glib.IO_IN, gui_callback, listen_sock);
	try:
		gtk.main()
	except:
		listen_sock.close()

main()
