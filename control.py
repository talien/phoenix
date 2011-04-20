#!/usr/bin/python

import os,sys,socket, struct
import gtk

class Rule:
	def __init__(self, pid, verdict, appname, source_zone, dest_zone):
		self.pid = pid
		self.verdict = verdict
		self.appname = appname
		self.source_zone = source_zone
		self.dest_zone = dest_zone

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

def phx_client_pack(sformat, data):
	i = 0
	amount = 0
	pd = 0
	result = ""
	while i < len(sformat):
		needpack = True
		if ( sformat[i] == 'S' ):
			result += struct.pack("<I", len(data[pd]))
			result += struct.pack("%ds" % len(data[pd]), data[pd])
			pd += 1
		elif ( sformat[i] == 'I' ):
			result += struct.pack("<I", data[pd])
			pd += 1
		elif( sformat[i] <= '9' and sformat[i] >= '0'):
			amount = amount*10 + (ord(sformat[i]) - 48);
			needpack = False
		elif ( sformat[i] == 's'):
			result += struct.pack("%ds" % amount, data[pd])
			pd += 1;
		if needpack:
			amount = 0
		i += 1
	return result


def parse_rule(data, position, zones):
	print "Data: %r, position:%d" % (data,position)
	(pid,verdict,srczone,destzone,strlen) = struct.unpack("IIIII",data[position:position+20])
	position += 20
	(appname,) = struct.unpack("<%ds" % strlen,data[position:position+strlen])
	position += strlen
	return (appname, position, Rule(pid, verdict, appname, zones[srczone][0], zones[destzone][0]))
	

def parse_chain(data, position, zones):
	print "Parsing chain, position='%d'" % position
	(hashes,) = struct.unpack("I",data[position:position+4])
	position = position + 4
	chain = {}
	appname = ""
	for i in range(0,hashes):
		(hash_value,) = struct.unpack("I",data[position:position+4])
		position = position + 4
		(appname, position, rule) = parse_rule(data,position, zones)
		chain[hash_value] = rule
	print "Returning from parse_chain: appname='%s', position='%d'" % (appname, position)
	return (appname, position, chain)

def parse_apptable(data, zones):
	position = 0;
	(chains,) = struct.unpack("I",data[position:position+4])
	print "chain number='%d'" % chains
	apptable = {}
	position += 4
	for i in range (0,chains):
		(appname, position, chain) = parse_chain(data,position, zones)
		print "Position after parse:position='%d'" % position
		apptable[appname] = chain
	return apptable

def parse_zones(data):
	position = 0
	zones = {}
	zones[0] = ("*","0.0.0.0/0")
	while position < len(data):
		(zlen,) = struct.unpack("<I", data[position:position+4])
		print "Unpacking zone, len='%d', position='%d'" % (zlen, position)
		position += 4
		(zonename, zoneid, network) = phx_client_unpack("SIS", data[position:position+zlen])
		zones[zoneid] = (zonename, network)
		position += zlen
	return zones

def pack_zones(zones):
	result = ""
	for zoneid, (zonename, network) in zones.iteritems():
		if (zoneid != 0):
			result += phx_client_pack("SIS",(zonename, zoneid, network));
	return result

def populate_zone_store(liststore, zones):
	for zoneid, (zonename, network) in zones.iteritems():
		if zoneid != 0:
			liststore.append((zoneid, zonename, network))

def populate_liststore(liststore, apptable):
	for name,chain in apptable.iteritems():
		for direction,rule in chain.iteritems():
			liststore.append((name, direction%4, rule.pid, rule.verdict,rule.source_zone, rule.dest_zone))


def zone_store_to_var(liststore):
	zones = {}
	liter = liststore.get_iter_first()
	while (liter):
		zid = liststore.get_value(liter, 0)
		zname = liststore.get_value(liter, 1)
		znetwork = liststore.get_value(liter, 2)
		liter = liststore.iter_next(liter)
		zones[zid] = (zname, znetwork)
	return zones;

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

def get_first_free_zone_id(liststore):
	zids = set()
	ziter = liststore.get_iter_first()
	while (ziter):
		zids = zids | set([liststore.get_value(ziter,0)])
		ziter = liststore.iter_next(ziter)
	for i in range(1,256):
		if (not i in zids):
			return i

class ZoneEditWindow(gtk.Window):
	def __init__(self, ziter, liststore):
		gtk.Window.__init__(self)
		layout = gtk.Fixed()
		zname = ""
		self.zid = get_first_free_zone_id(liststore)
		znet = ""
		if (ziter != None):
			self.wtype = 0
			self.zid = liststore.get_value(ziter, 0)
			zname = liststore.get_value(ziter, 1)
			znet = liststore.get_value(ziter, 2)
		self.ziter = ziter
		self.liststore = liststore
		self.name_entry = gtk.Entry()
		self.name_entry.set_text(zname)
		self.network_entry = gtk.Entry()
		self.network_entry.set_text(znet)
		layout.put(gtk.Label("Zone id"), 0, 0)
		layout.put(gtk.Label("Zone name"),0,30)
		layout.put(gtk.Label("Network"),0,60)
		layout.put(gtk.Label("%d" % self.zid), 100,0)
		layout.put(self.name_entry,100,30)
		layout.put(self.network_entry, 100,60)
		okbutton = gtk.Button("OK")
		cancelbutton = gtk.Button("Cancel")
		okbutton.connect("clicked", self.ok_button_clicked, None)
		cancelbutton.connect("clicked", self.cancel_button_clicked, None)
		layout.put(okbutton,30,150);
		layout.put(cancelbutton,120,150);

		self.resize(200,200);
		self.add(layout)
		self.show_all()

	def ok_button_clicked(self, widget, data=None):
		if (self.ziter !=None):
			self.liststore.set_value(self.ziter, 1, self.name_entry.get_text())
			self.liststore.set_value(self.ziter, 2, self.network_entry.get_text())
		else:
			self.liststore.append((self.zid, self.name_entry.get_text(),self.network_entry.get_text()))
		self.destroy()

	def cancel_button_clicked(self, widget, data=None):
		self.destroy()
		
class MainWindow(gtk.Window):


	def __init__(self,apptable,zones):
		gtk.Window.__init__(self)
		self.zones = zones
		self.liststore = gtk.ListStore(str, int, int,int, str, str)
		self.zonestore = gtk.ListStore(int, str, str)
		populate_liststore(self.liststore, apptable)
		populate_zone_store(self.zonestore, zones)
		treeview = gtk.TreeView(self.liststore)
		self.zoneview = gtk.TreeView(self.zonestore)

		vbox = gtk.VBox(False, 0)

		create_cell(treeview, "Program", 0)
		create_cell(treeview, "Direction", 1)
		create_cell(treeview, "Pid", 2)
		create_cell(treeview, "Verdict", 3)
		create_cell(treeview, "Source zone", 4)
		create_cell(treeview, "Destination zone", 5)

		create_cell(self.zoneview, "Zone ID", 0)
		create_cell(self.zoneview, "Zone name", 1)
		create_cell(self.zoneview, "Network", 2)

		self.connect("delete_event", self.destroy);

		self.resize(400,400)

		zonebuttons = gtk.HBox(False, 0)
		
		zone_commit_button = gtk.Button("Commit")
		zone_edit_button = gtk.Button("Edit zone...")
		zone_add_button = gtk.Button("Add zone...");
		
		zonebuttons.pack_start(zone_add_button)
		zonebuttons.pack_start(zone_edit_button)
		zonebuttons.pack_start(zone_commit_button)
			
		zone_box = gtk.VBox(False,0)

		zone_box.pack_start(self.zoneview)
		zone_box.pack_end(zonebuttons)

		vbox.pack_start(treeview,True, True, 0)
		vbox.pack_end(zone_box, True, True, 0)

		zone_add_button.connect("clicked", self.zone_add_clicked, None)
		zone_edit_button.connect("clicked", self.zone_edit_clicked, None)
		zone_commit_button.connect("clicked", self.zone_commit_clicked, None)

		self.add(vbox)
		self.show_all()

	def zone_commit_clicked(self, widget, data = None):
		self.zones = zone_store_to_var(self.zonestore)
		test = pack_zones(self.zones)
		print "Zone pack test '%r'" % test
		data = send_command("SZN"+test);

	def zone_edit_clicked(self, widget, data = None):
		(model, ziter) = self.zoneview.get_selection().get_selected()
		if (ziter == None):
			print "No selection"
			return
		win = ZoneEditWindow(ziter, self.zonestore)
		win.show()

	def zone_add_clicked(self, widget, data = None):
		win = ZoneEditWindow(None, self.zonestore)
		win.show()

	def destroy(self, widget, data = None):
		gtk.main_quit();
		return False
	
def main():
	data = send_command("GZN");
	zones = parse_zones(data)
	data = send_command("GET");
	apptable = parse_apptable(data, zones);
	window = MainWindow(apptable, zones)
	gtk.main()
	
main()
