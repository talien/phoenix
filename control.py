#!/usr/bin/python

import os,sys,socket, struct
import gtk

class Rule:
	def __init__(self, pid, verdict, appname):
		self.pid = pid
		self.verdict = verdict
		self.appname = appname

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

def parse_zones(data):
	position = 0
	zones = {}
	while position < len(data):
		(zlen,) = struct.unpack("<I", data[position:position+4])
		print "Unpacking zone, len='%d', position='%d'" % (zlen, position)
		position += 4
		(zonename, zoneid, network) = phx_client_unpack("SIS", data[position:position+zlen])
		zones[zoneid] = (zonename, network)
		position += zlen
	return zones

def populate_zone_store(liststore, zones):
	for zoneid, (zonename, network) in zones.iteritems():
		liststore.append((zoneid, zonename, network))

def populate_liststore(liststore, apptable):
	for name,chain in apptable.iteritems():
		for direction,rule in chain.iteritems():
			liststore.append((name, direction%4, rule.pid, rule.verdict))

def send_command(command, cdata = None):
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.connect("phxdsock")
	s.send(command)
	data = s.recv(4096)
	print "len='%d', data='%r'" % (len(data), data)
	s.close()
	return data

def create_cell(treeview, column_name = "Column", column_text = 0):
	cell = gtk.CellRendererText()
	col = gtk.TreeViewColumn( column_name )
	col.pack_start(cell, True)
	col.set_attributes(cell,text=column_text)
	treeview.append_column(col)


class MainWindow(gtk.Window):


	def __init__(self,apptable,zones):
		gtk.Window.__init__(self)
		liststore = gtk.ListStore(str, int, int,int)
		zonestore = gtk.ListStore(int, str, str)
		populate_liststore(liststore, apptable)
		populate_zone_store(zonestore, zones)
		treeview = gtk.TreeView(liststore)
		zoneview = gtk.TreeView(zonestore)

		vbox = gtk.VBox(False, 0)

		create_cell(treeview, "Program", 0)
		create_cell(treeview, "Direction", 1)
		create_cell(treeview, "Pid", 2)
		create_cell(treeview, "Verdict", 3)

		create_cell(zoneview, "Zone ID", 0)
		create_cell(zoneview, "Zone name", 1)
		create_cell(zoneview, "Network", 2)

		self.connect("delete_event", self.destroy);

		self.resize(400,400)

		vbox.pack_start(treeview,True, True, 0)
		vbox.pack_end(zoneview, True, True, 0)

		self.add(vbox)
		self.show_all()

	def destroy(self, widget, data = None):
		gtk.main_quit();
		return False
	
def main():
	data = send_command("GET");
	apptable = parse_apptable(data);
	data = send_command("GZN");
	zones = parse_zones(data)
	window = MainWindow(apptable, zones)
	gtk.main()
	
main()
