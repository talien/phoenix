#!/usr/bin/python
import gtk, gobject
import os,sys,socket, getpass, select, struct

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
		
		

def phx_client_unpack(sformat, data):
	i = 0
	amount = 0
	pd = 0
	t = ()
	while i < len(sformat):
		needpack = True
		if ( sformat[i] == 'S' ):
			(slen,) = struct.unpack("<I", data[pd:pd+4])
			pd += 4
			gvar = struct.unpack("%ds" % slen, data[pd:pd+slen])
			pd += slen
		elif ( sformat[i] == 'I' ):
			gvar = struct.unpack("<I", data[pd:pd+4])
			pd += 4
		elif( sformat[i] <= '9' and sformat[i] >= '0'):
			amount = amount*10 + (ord(sformat[i]) - 48);
			needpack = False
		elif ( sformat[i] == 's'):
			gvar = struct.unpack("%ds" % amount, data[pd:pd+amount])
			pd += amount;
		if needpack:
			t = t + gvar
			amount = 0
		i += 1
	return t

def process_data(data):
	(process_name, pid, srcip, sport, destip, dport, direction, srczone, destzone, sz_name, dz_name, cmd_line) = phx_client_unpack("SI4sI4sIIIISSS",data)
	dialog = ClientWindow(process_name, pid, srcip, sport, destip, dport, direction, srczone, destzone, sz_name, dz_name, cmd_line)
	resp = dialog.run()
	if (resp == gtk.RESPONSE_YES):
		verdict = 1 # ACCEPTED
	else:
		verdict = 2 # DENIED
	(pid, srczone, destzone) = dialog.calculate_values()
	dialog.destroy()
	return struct.pack("<IIII", verdict, srczone, destzone, pid);
	
def gui_timer_callback(lsock):
	pollobj = select.poll()
	pollobj.register(lsock, select.POLLIN)
	polled = pollobj.poll(0)
	if (len(polled) > 0):
		(newsock,tmp) = lsock.accept()
		data = newsock.recv(4096)
		print "data got, length='%d', data='%r'" % (len(data), data)
		send_data = process_data(data)
		print "sending data: '%r'" % send_data
		newsock.send(send_data)
		newsock.close()
	gobject.timeout_add(10, gui_timer_callback, lsock)

def setup_socket():
	sock_name = "phxsock-" + getpass.getuser()
	if (os.path.exists(sock_name)):
		os.unlink(sock_name)
	listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	listen_sock.bind(sock_name)
	listen_sock.listen(5)
	return listen_sock

def main():
	listen_sock = setup_socket()
	gobject.timeout_add(10,gui_timer_callback, listen_sock)
	try:
		gtk.main()
	except:
		listen_sock.close()

main()
