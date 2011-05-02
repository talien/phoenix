#!/usr/bin/python

import os,sys,socket, struct
import gtk

change_store = []

dir_const = { "OUTBOUND" : 0, "INBOUND" : 1 }
verdict_const = { "NEW" : 0 , "ACCEPTED" : 1, "DENIED" : 2, "DENY_CONN" : 3, "ACCEPT_CONN": 5, "ASK" : 7, "WAIT_FOR_ANSWER" : 8}

apptable = {}

class Config:
	def __init__(self):
		self.apptable = {}
		self.zones = {}
		self.liststore = gtk.ListStore(str, int, int,int, int,str, int,str)
		self.zonestore = gtk.ListStore(int, str, str)
		self.change_store = []


class Rule:
	def __init__(self, appname = "", pid = 0, direction = 0, verdict = 0, src_zone_id = 0, source_zone = "*", dst_zone_id = 0, dest_zone = "*"):
		self.pid = pid
		self.verdict = verdict
		self.appname = appname
		self.source_zone = source_zone
		self.dest_zone = dest_zone
		self.src_zone_id = src_zone_id
		self.dst_zone_id = dst_zone_id
		self.direction = direction

	def __eq__(self, other):
		return ((self.pid == other.pid) and
				(self.verdict == other.verdict) and
				(self.appname == other.appname) and
				(self.source_zone == other.source_zone) and
				(self.dest_zone == other.dest_zone) and
				(self.src_zone_id == other.src_zone_id) and
				(self.dst_zone_id == other.dst_zone_id) and
				(self.direction == other.direction))

	def __ne__(self, other):
		return not self.__eq__(other)

	def __str__(self):
		return "Name: %s, pid:%d, direction:%d, verdict:%d, src_zone_id:%d, dst_zone_id:%d" % (self.appname, self.pid, self.direction, self.verdict, self.src_zone_id, self.dst_zone_id)

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
	(pid,verdict,srczone,destzone,direction, strlen) = struct.unpack("IIIIII",data[position:position+24])
	position += 24
	(appname,) = struct.unpack("<%ds" % strlen,data[position:position+strlen])
	position += strlen
	return (appname, position, Rule(appname, pid, direction, verdict, srczone, zones[srczone][0], destzone, zones[destzone][0]))
	

def parse_chain(data, position, zones):
	print "Parsing chain, position='%d'" % position
	(hashes,) = struct.unpack("I",data[position:position+4])
	position = position + 4
	chain = []
	appname = ""
	for i in range(0,hashes):
		(appname, position, rule) = parse_rule(data,position, zones)
		chain.append(rule)
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

def refresh_liststore(liststore, papptable, changes):
	print "Refreshing liststore, papptable_len:%d" % len(papptable)
	liststore.clear()
	new_table = apptable_merge_changes(papptable, changes)
	print "new_table length: %d" % len(new_table)
	populate_liststore(liststore, new_table)

def apptable_dump(papptable):
	print "===="
	print "Dumping apptable, chain_num='%d'" % len(papptable)
	for name, chain in papptable.iteritems():
		print "Dumping chain, name='%s', chain_items='%d'" % (name,len(chain))
		for rule in chain:
			print "Rule, rule='%s'" % rule
	print "===="

def apptable_delete_rule(papptable, rule):
	#note: delete chain if become empty
	print "Deleting rule, %s" % rule
	chain = papptable[rule.appname]
	i = 0
	for crule in chain:
		if (rule == crule):
			print "deleting rule chain:%s id:%d" % (rule.appname, i)
			print "Deleted rule: %s" % crule
			chain.remove(crule)
		i += 1

def apptable_add_rule(papptable, rule):
	print "Adding rule, %s" % rule
	if rule.appname in papptable:
		chain = papptable[rule.appname]
		chain.append(rule)		
	else:
		chain = []
		chain.append(rule)
		papptable[rule.appname] = chain
			
def apptable_copy(papptable):
	new_table = {}
	print "Copying apptable, chains:%d" % len(papptable)
	for name, chain in papptable.iteritems():
		new_table[name] = list(chain)
	return new_table

def apptable_merge_changes(papptable, changes):
	new_table = apptable_copy(papptable)
	print "merge_changes, new_table_len:%d" % len(new_table)
	for (ctype,rule) in changes:
		print "%s" % ctype
		apptable_dump(new_table)
		if (ctype == "DELETE"):
			apptable_delete_rule(new_table, rule)
		if (ctype == "ADD"):
			apptable_add_rule(new_table, rule)
	return new_table

def populate_liststore(liststore, papptable):
	for name,chain in papptable.iteritems():
		for rule in chain:
			liststore.append((name, rule.pid, rule.direction, rule.verdict,rule.src_zone_id, rule.source_zone, rule.dst_zone_id, rule.dest_zone))


def zone_store_to_var(liststore, append_wildcard = False):
	zones = {}
	if append_wildcard:
		zones[0] = ("*","0.0.0.0/0")
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

def get_zone_id_from_name(zname, zones):
	for zoneid, (zonename, network) in zones.iteritems():
		if (zonename == zname):
			return zoneid

	#hmm, perhaps i should use some *normal* error handling? (exceptions)
	return -1

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

class RuleEditWindow(gtk.Window):
	def fill_zones(self, combobox, zonestore, active):
		zones = zone_store_to_var(zonestore, True)
		self.zones = zones
		index = 0
		act_ind = 0
		for zoneid, (zonename, network) in zones.iteritems():
			combobox.append_text(zonename)
			if (zonename == active):
				act_ind = index
			index += 1
		combobox.set_active(act_ind)

	def __init__(self, riter, cfg):
		gtk.Window.__init__(self)
		layout = gtk.Fixed()
		rulestore = cfg.liststore
		self.mode = ""
		self.rule = None
		if (riter == None):
			self.mode = "ADD"
			self.rule = Rule()
		else:
			self.rule = Rule(rulestore.get_value(riter, 0), rulestore.get_value(riter, 1),rulestore.get_value(riter, 2),rulestore.get_value(riter, 3),rulestore.get_value(riter, 4),rulestore.get_value(riter, 5),rulestore.get_value(riter, 6), rulestore.get_value(riter, 7))
			self.mode = "EDIT"		

		self.cfg = cfg
		layout.put(gtk.Label("Application name"), 10, 10) 
		layout.put(gtk.Label("Application pid"), 10, 40)
		layout.put(gtk.Label("Direction"), 10, 70)
		layout.put(gtk.Label("Source Zone"), 10, 100)
		layout.put(gtk.Label("Destination Zone"), 10, 130)
		layout.put(gtk.Label("Verdict"), 10, 160)

		self.name_entry = gtk.Entry()
		self.name_entry.set_text(self.rule.appname)
		layout.put(self.name_entry, 150,7)

		self.pid_entry = gtk.Entry()
		self.pid_entry.set_text("%s" % self.rule.pid)
		layout.put(self.pid_entry, 150, 37)

		self.dir_entry = gtk.combo_box_new_text()
		self.dir_entry.append_text("OUTBOUND")
		self.dir_entry.append_text("INBOUND")
		self.dir_entry.set_active(self.rule.direction)
		layout.put(self.dir_entry, 150, 67)

		self.src_zone_entry = gtk.combo_box_new_text()
		self.fill_zones(self.src_zone_entry, self.cfg.zonestore, self.rule.source_zone)
		layout.put(self.src_zone_entry, 150, 97)

		self.dst_zone_entry = gtk.combo_box_new_text()
		self.fill_zones(self.dst_zone_entry, self.cfg.zonestore, self.rule.dest_zone)
		layout.put(self.dst_zone_entry, 150, 127)

		self.verdict_entry = gtk.combo_box_new_text()
		self.verdict_entry.append_text("NEW")
		self.verdict_entry.append_text("ACCEPTED")
		self.verdict_entry.append_text("DENIED")
		self.verdict_entry.append_text("DENY_CONN")
		self.verdict_entry.append_text("ACCEPT_CONN")
		self.verdict_entry.append_text("ASK")
		self.verdict_entry.set_active(self.rule.verdict)
		layout.put(self.verdict_entry, 150, 157)

		cancelbutton = gtk.Button("Cancel")
		layout.put(cancelbutton, 10, 250)

		okbutton = gtk.Button("Ok")
		layout.put(okbutton, 200, 250)


		cancelbutton.connect("clicked", self.cancel_button_clicked, None)
		okbutton.connect("clicked", self.ok_button_clicked, None)

		self.resize(350,300)
		self.add(layout)
		self.show_all()

	def create_rule(self):
		pid = int(self.pid_entry.get_text())
		direction = dir_const[self.dir_entry.get_active_text()]
		verdict = verdict_const[self.verdict_entry.get_active_text()]
		src_zid = get_zone_id_from_name(self.src_zone_entry.get_active_text(), self.zones)
		dst_zid = get_zone_id_from_name(self.dst_zone_entry.get_active_text(), self.zones)
		result = Rule(self.name_entry.get_text(), pid, direction, verdict, src_zid, self.src_zone_entry.get_active_text(), dst_zid, self.dst_zone_entry.get_active_text())
		return result

	def cancel_button_clicked(self, widget, data = None):
		self.destroy()
		
	def ok_button_clicked(self, widget, data = None):
		rule = self.create_rule()
		if self.mode == "ADD":
			change_store.append(("ADD", rule))
			refresh_liststore(self.cfg.liststore, self.cfg.apptable, change_store)
		else:
			if rule != self.rule:
				change_store.append(("DELETE", self.rule))
				change_store.append(("ADD",rule))
				refresh_liststore(self.cfg.liststore, self.cfg.apptable, change_store)
		self.destroy()

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


	def __init__(self,cfg):
		gtk.Window.__init__(self)
		self.cfg = cfg
		refresh_liststore(cfg.liststore, cfg.apptable, cfg.change_store)
		populate_zone_store(cfg.zonestore, cfg.zones)
		self.treeview = gtk.TreeView(cfg.liststore)
		self.zoneview = gtk.TreeView(cfg.zonestore)

		vbox = gtk.VBox(False, 0)

		rule_box = gtk.VBox(False, 0)

		create_cell(self.treeview, "Program", 0)
		create_cell(self.treeview, "Direction", 2)
		create_cell(self.treeview, "Pid", 1)
		create_cell(self.treeview, "Verdict", 3)
		create_cell(self.treeview, "Source zone", 5)
		create_cell(self.treeview, "Destination zone", 7)

		create_cell(self.zoneview, "Zone ID", 0)
		create_cell(self.zoneview, "Zone name", 1)
		create_cell(self.zoneview, "Network", 2)

		self.connect("delete_event", self.destroy);

		self.resize(400,400)

		rulebuttons = gtk.HBox(False, 0)

		rule_edit = gtk.Button("Edit rule...")
		rule_add = gtk.Button("Add...")
		rulebuttons.pack_start(rule_add)
		rulebuttons.pack_start(rule_edit)

		rule_box.pack_start(self.treeview)
		rule_box.pack_start(rulebuttons)

		rule_edit.connect("clicked", self.rule_edit_clicked, None)
		rule_add.connect("clicked", self.rule_add_clicked, None)

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

		vbox.pack_start(rule_box, True, True, 0)
		vbox.pack_end(zone_box, True, True, 0)

		zone_add_button.connect("clicked", self.zone_add_clicked, None)
		zone_edit_button.connect("clicked", self.zone_edit_clicked, None)
		zone_commit_button.connect("clicked", self.zone_commit_clicked, None)

		self.add(vbox)
		self.show_all()

	def zone_commit_clicked(self, widget, data = None):
		self.zones = zone_store_to_var(self.cfg.zonestore)
		test = pack_zones(self.cfg.zones)
		print "Zone pack test '%r'" % test
		data = send_command("SZN"+test);

	def zone_edit_clicked(self, widget, data = None):
		(model, ziter) = self.zoneview.get_selection().get_selected()
		if (ziter == None):
			print "No selection"
			return
		win = ZoneEditWindow(ziter, self.cfg.zonestore)
		win.show()

	def rule_add_clicked(self, widget, data = None):
		win = RuleEditWindow(None, self.cfg)
		win.show()

	def rule_edit_clicked(self, widget, data = None):
		(model, riter) = self.treeview.get_selection().get_selected()
		if (riter == None):
			print "No selection"
			return
		win = RuleEditWindow(riter, self.cfg)
		win.show()

	def zone_add_clicked(self, widget, data = None):
		win = ZoneEditWindow(None, self.cfg.zonestore)
		win.show()

	def destroy(self, widget, data = None):
		gtk.main_quit();
		return False
	
def main():
	cfg = Config()
	data = send_command("GZN");
	cfg.zones = parse_zones(data)
	data = send_command("GET");
	cfg.apptable = parse_apptable(data, cfg.zones);
	window = MainWindow(cfg)
	gtk.main()
	
main()
