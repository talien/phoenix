#!/usr/bin/python
import gtk, gobject
import os,sys,socket, getpass, select, struct

dir_map = { 0 : "Outbound", 1 : "Inbound" }



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
	(process_name, pid, srcip, sport, destip, dport, direction, srczone, destzone, sz_name, dz_name) = phx_client_unpack("SI4sI4sIIIISS",data)
	message = ""
	if (direction == 0):
		message = "The program: '%s'\n wants to reach internet\n '%s' -> '%s'\ndo you accept?" % (process_name, sz_name, dz_name)
	else:
		message = "The program: '%s'\n wants to accept connections\n '%s' -> '%s'\ndo you accept?" % (process_name, sz_name, dz_name)
	dialog = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO, gtk.BUTTONS_YES_NO, message)
	resp = dialog.run()
	if (resp == gtk.RESPONSE_YES):
		verdict = 1 # ACCEPTED
	else:
		verdict = 2 # DENIED
	dialog.destroy()
	return struct.pack("<III", verdict, srczone, destzone);
	
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
