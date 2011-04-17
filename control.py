#!/usr/bin/python

import os,sys,socket, struct
import gtk

class Rule:
	def __init__(self, pid, verdict, appname):
		self.pid = pid
		self.verdict = verdict
		self.appname = appname

def parse_rule(data, position):
	print "Data: %r, position:%d" % (data,position)
	(pid,verdict,srczone,destzone,strlen) = struct.unpack("IIIII",data[position:position+20])
	position += 20
	(appname,) = struct.unpack("<%ds" % strlen,data[position:position+strlen])
	position += strlen
	return (appname, position, Rule(pid, verdict,appname))
	

def parse_chain(data, position):
	print "Parsing chain, position='%d'" % position
	(hashes,) = struct.unpack("I",data[position:position+4])
	position = position + 4
	chain = {}
	appname = ""
	for i in range(0,hashes):
		(hash_value,) = struct.unpack("I",data[position:position+4])
		position = position + 4
		(appname, position, rule) = parse_rule(data,position)
		chain[hash_value] = rule
	print "Returning from parse_chain: appname='%s', position='%d'" % (appname, position)
	return (appname, position, chain)

def parse_apptable(data):
	position = 0;
	(chains,) = struct.unpack("I",data[position:position+4])
	print "chain number='%d'" % chains
	apptable = {}
	position += 4
	for i in range (0,chains):
		(appname, position, chain) = parse_chain(data,position)
		print "Position after parse:position='%d'" % position
		apptable[appname] = chain
	return apptable

def populate_liststore(liststore, apptable):
	for name,chain in apptable.iteritems():
		for direction,rule in chain.iteritems():
			liststore.append((name, direction%4, rule.pid, rule.verdict))

class MainWindow(gtk.Window):
	def __init__(self,apptable):
		gtk.Window.__init__(self)
		liststore = gtk.ListStore(str, int, int,int)
		populate_liststore(liststore, apptable)
		treeview = gtk.TreeView(liststore)

		cell = gtk.CellRendererText()
		col = gtk.TreeViewColumn("Program")
		col.pack_start(cell, True)
		col.set_attributes(cell,text=0)
		treeview.append_column(col)

		cell = gtk.CellRendererText()
		col = gtk.TreeViewColumn("Direction")
		col.pack_start(cell, True)
		col.set_attributes(cell,text=1)
		treeview.append_column(col)

		cell = gtk.CellRendererText()
		col = gtk.TreeViewColumn("Pid")
		col.pack_start(cell, True)
		col.set_attributes(cell,text=2)
		treeview.append_column(col)

		cell = gtk.CellRendererText()
		col = gtk.TreeViewColumn("Verdict")
		col.pack_start(cell, True)
		col.set_attributes(cell,text=3)
		treeview.append_column(col)


		self.add(treeview)
		self.show_all()
		
def main():
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.connect("phxdsock")
	s.send("GET")
	data = s.recv(4096)
	print "len='%d', data='%r'" % (len(data), data)
	apptable = parse_apptable(data);
	window = MainWindow(apptable)
	gtk.main()
	
main()
