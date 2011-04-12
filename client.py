#!/usr/bin/python
import gtk, gobject
import os,sys,socket, getpass, select, struct

dir_map = { 0 : "Outbound", 1 : "Inbound" }

def process_data(data):
	(strlen) = struct.unpack("I", data[:4])
	print "strlen = %d" % strlen
	format_string = "<I%dsI4sI4sIIII" % strlen
	print format_string
	# FIXME: refcount handling should be on server side
 	(strlen, process_name, pid, srcip, sport, destip, dport, verdict, direction,refcnt) =  struct.unpack(format_string, data)
#	print "I want to accept, pid='%d', process='%s', verdict='%d', direction='%s'" % (pid, process_name, verdict, dir_map[direction])
	dialog = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO, gtk.BUTTONS_YES_NO, "The program: '%s', wants to reach internet, do you accept?" % process_name);
	resp = dialog.run()
	if (resp == gtk.RESPONSE_YES):
		verdict = 1 # ACCEPTED
	else:
		verdict = 2 # DENIED
	return struct.pack("<I%dsI4sI4sIIII" % strlen,strlen, process_name, pid, srcip, sport, destip, dport, verdict, direction, refcnt)
	
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
