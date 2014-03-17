#!/usr/bin/python

import os,sys,socket, struct, re
import gtk
from optparse import OptionParser
from phxlib import *

dir_const = { "OUTBOUND" : 0, "INBOUND" : 1 }
verdict_const = { "NEW" : 0 , "ACCEPTED" : 1, "DENIED" : 2, "DENY_CONN" : 3, "ACCEPT_CONN": 5, "ASK" : 7, "WAIT_FOR_ANSWER" : 8}
verdict_dir = { 0 : "NEW", 1: "ACCEPTED", 2: "DENIED", 3 : "DENY_CONN", 5 : "ACCEPT_CONN", 7 : "ASK", 8 : "WAIT_FOR_ANSWER" }
options = None
socket_path = "/var/run/"

def debug(debug_str):
    if options.need_debug:
        print debug_str

class Config:
    def __init__(self):
        self.apptable = {}
        self.zones = {}
        self.liststore = gtk.ListStore(str, int, int,int, int,str, int,str)
        self.change_store = []

    def export_rules(self, filename):
        new_table = self.apptable.merge_changes(self.change_store)
        new_table.export(filename)

    def refresh_liststore(self):
        debug("Refreshing liststore, papptable_len:%d" % len(self.apptable.apptable))
        self.liststore.clear()
        new_table = self.apptable.merge_changes(self.change_store)
        debug("new_table length: %d" % len(new_table.apptable))
        new_table.populate(self.liststore)

                

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

    def serialize(self):
        return phx_client_pack("SIIIII", (self.appname, self.pid, self.direction, self.verdict, self.src_zone_id, self.dst_zone_id))

    def save(self):
        result = "[rule]\n program = %s\n" % self.appname
        if self.pid != 0:
            result += " pid = %s\n" % self.pid
        if self.verdict == 1:
            result += " verdict = accepted\n"
        elif self.verdict == 2:
            result += " verdict = denied\n"

        if self.direction == 0:
            result += " direction = out\n"
        elif self.direction == 1:
            result += " direction = in\n"

        return result
    def parse(self, data, position, zones):
        debug("Data: %r, position:%d" % (data,position))
        rlen, (pid,verdict,srczone,destzone,direction, appname) = phx_client_unpack("IIIIIS", data[position:])
        self.__init__(appname, pid, direction, verdict, srczone, zones[srczone][0], destzone, zones[destzone][0])
        return position + rlen

class Apptable:
    def __init__(self):
        self.apptable = {}

    def parse(self, data, zones):
        position = 0;
        (chains,) = struct.unpack("I",data[position:position+4])
        debug("chain number='%d'" % chains)
        self.apptable = {}
        position += 4
        for i in range (0,chains):
            position = self.parse_chain(data, position, zones)
        
    def parse_chain(self, data, position, zones):
        debug("Parsing chain, position='%d'" % position)
        (hashes,) = struct.unpack("I",data[position:position+4])
        position = position + 4
        chain = []
        appname = ""
        rule = Rule()
        for i in range(0,hashes):
            position = rule.parse(data, position, zones)
            self.add_rule(rule)
        debug("Returning from parse_chain: appname='%s', position='%d'" % (appname, position))
        return position
    
    def delete_rule(self, rule):
        #note: delete chain if become empty
        debug("Deleting rule, %s" % rule)
        chain = self.apptable[rule.appname]
        i = 0
        for crule in chain:
            if (rule == crule):
                debug("Deleted rule, id='%d' rule='%s'" % (i, crule))
                chain.remove(crule)
            i += 1

    def add_rule(self, rule):
        debug("Adding rule, %s" % rule)
        if rule.appname in self.apptable:
            chain = self.apptable[rule.appname]
            chain.append(rule)        
        else:
            chain = []
            chain.append(rule)
            self.apptable[rule.appname] = chain

    def copy(self):
        new_table = Apptable()
        debug("Copying apptable, chains:%d" % len(self.apptable))
        for name, chain in self.apptable.iteritems():
            new_table.apptable[name] = list(chain)
        return new_table

    def merge_changes(self, changes):
        new_table = self.copy()
        debug("merge_changes, new_table_len:%d" % len(new_table.apptable))
        for (ctype,rule) in changes:
            debug("%s" % ctype)
#            apptable_dump(new_table)
            if (ctype == "DELETE"):
                new_table.delete_rule(rule)
            if (ctype == "ADD"):
                new_table.add_rule(rule)
        return new_table

    def export(self, filename):        
        f = open(filename,"w")
        for appname, chain in self.apptable.iteritems():
            for rule in chain:
                if rule.verdict == 1 or rule.verdict == 2:
                    f.write(rule.save())
        f.close()
    def populate(self,liststore):
        for name,chain in self.apptable.iteritems():
            for rule in chain:
                liststore.append((name, rule.pid, rule.direction, rule.verdict,rule.src_zone_id, rule.source_zone, rule.dst_zone_id, rule.dest_zone))

    def dump(self):
        debug("====")
        debug("Dumping apptable, chain_num='%d'" % len(self.apptable))
        for name, chain in self.apptable.iteritems():
            debug("Dumping chain, name='%s', chain_items='%d'" % (name,len(chain)))
            for rule in chain:
                debug("Rule, rule='%s'" % rule)
        debug("====")

class Zones:
    def __init__(self):
        self.zones = {}
        self.zonestore = gtk.ListStore(int, str, str)
        
    def parse(self,data):
        position = 0
        self.zones = {}
        self.zones[0] = ("*","0.0.0.0/0")
        while position < len(data):
            (zlen,) = struct.unpack("<I", data[position:position+4])
            debug("Unpacking zone, len='%d', position='%d'" % (zlen, position))
            position += 4
            tmp,(zonename, zoneid, network) = phx_client_unpack("SIS", data[position:position+zlen])
            self.zones[zoneid] = (zonename, network)
            position += zlen
        self.populate()

    def serialize(self):
        self.fill()
        result = ""
        for zoneid, (zonename, network) in self.zones.iteritems():
            if (zoneid != 0):
                result += phx_client_pack("SIS",(zonename, zoneid, network));
        return result

    def get_id_from_name(self,zname):
        for zoneid, (zonename, network) in self.zones.iteritems():
            if (zonename == zname):
                return zoneid

        #hmm, perhaps i should use some *normal* error handling? (exceptions)
        return -1

    def populate(self):
        for zoneid, (zonename, network) in self.zones.iteritems():
            if zoneid != 0:
                self.zonestore.append((zoneid, zonename, network))

    def fill(self, append_wildcard = False):
        self.zones = {}
        if append_wildcard:
            self.zones[0] = ("*","0.0.0.0/0")
        liter = self.zonestore.get_iter_first()
        while (liter):
            zid = self.zonestore.get_value(liter, 0)
            zname = self.zonestore.get_value(liter, 1)
            znetwork = self.zonestore.get_value(liter, 2)
            liter = self.zonestore.iter_next(liter)
            self.zones[zid] = (zname, znetwork)
    def get_first_free_zone_id(self):
        zids = set()
        ziter = self.zonestore.get_iter_first()
        while (ziter):
            zids = zids | set([self.zonestore.get_value(ziter,0)])
            ziter = self.zonestore.iter_next(ziter)
        for i in range(1,256):
            if (not i in zids):
                return i


    def add(self, zid, name, netmask):
        self.zonestore.append((zid, name, netmask))


    def modify(self, ziter, name, netmask):
        self.zonestore.set_value(ziter, 1, name)
        self.zonestore.set_value(ziter, 2, netmask)

    def get_name(self, ziter):
        return self.zonestore.get_value(ziter, 1)

    def delete(self, ziter):
        return self.zonestore.remove(ziter)

def phx_serialize_changes(changelist):
    list_len = len(changelist)
    result = phx_client_pack("I",(list_len,))
    for (mode,rule) in changelist:
        int_mode = 0
        if (mode == "ADD"):
            int_mode = 0
        else:
            int_mode = 1
        result += phx_client_pack("I",(int_mode,))
        result += rule.serialize()
    return result    


def send_command(command, cdata = None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if options.socket_file:
        s.connect(options.socket_file)
    else:
        s.connect(socket_path + "phxdsock")
    s.send(command)
    data = s.recv(4096)
    debug("len='%d', data='%r'" % (len(data), data))
    s.close()
    return data

def create_cell(treeview, column_name = "Column", column_text = 0, render_func = None):
    cell = gtk.CellRendererText()
    col = gtk.TreeViewColumn( column_name )
    col.pack_start(cell, True)
    if (render_func == None):
        col.set_attributes(cell,text=column_text)
    else:
        col.set_cell_data_func(cell, render_func, None)
    treeview.append_column(col)

class RuleEditWindow(gtk.Window):
    def fill_zones(self, combobox, zonestore, active):
        #zones = zone_store_to_var(zonestore, True)
        self.zones = zonestore
        index = 0
        act_ind = 0
        for zoneid, (zonename, network) in self.zones.zones.iteritems():
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
        self.fill_zones(self.src_zone_entry, self.cfg.zones, self.rule.source_zone)
        layout.put(self.src_zone_entry, 150, 97)

        self.dst_zone_entry = gtk.combo_box_new_text()
        self.fill_zones(self.dst_zone_entry, self.cfg.zones, self.rule.dest_zone)
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
        src_zid = self.zones.get_id_from_name(self.src_zone_entry.get_active_text())
        dst_zid = self.zones.get_id_from_name(self.dst_zone_entry.get_active_text())
        result = Rule(self.name_entry.get_text(), pid, direction, verdict, src_zid, self.src_zone_entry.get_active_text(), dst_zid, self.dst_zone_entry.get_active_text())
        return result

    def cancel_button_clicked(self, widget, data = None):
        self.destroy()
        
    def ok_button_clicked(self, widget, data = None):
        rule = self.create_rule()
        if self.mode == "ADD":
            self.cfg.change_store.append(("ADD", rule))
            self.cfg.refresh_liststore()
        else:
            if rule != self.rule:
                self.cfg.change_store.append(("DELETE", self.rule))
                self.cfg.change_store.append(("ADD",rule))
                self.cfg.refresh_liststore()
        self.destroy()

class ZoneEditWindow(gtk.Window):
    def __init__(self, ziter, cfg):
        gtk.Window.__init__(self)
        layout = gtk.Fixed()
        zname = ""
        self.cfg = cfg
        self.zid = self.cfg.zones.get_first_free_zone_id()
        znet = ""
        if (ziter != None):
            self.wtype = 0
            self.zid = self.cfg.zones.zonestore.get_value(ziter, 0)
            zname = self.cfg.zones.zonestore.get_value(ziter, 1)
            znet = self.cfg.zones.zonestore.get_value(ziter, 2)
        self.ziter = ziter
        self.name_entry = gtk.Entry()
        self.name_entry.set_text(zname)
        self.network_entry = gtk.Entry()
        self.network_entry.set_text(znet)
        layout.put(gtk.Label("Zone id"), 10, 10)
        layout.put(gtk.Label("Zone name"),10,40)
        layout.put(gtk.Label("Network"),10,70)
        layout.put(gtk.Label("%d" % self.zid), 110,10)
        layout.put(self.name_entry,110,40)
        layout.put(self.network_entry, 110,70)
        okbutton = gtk.Button("OK")
        cancelbutton = gtk.Button("Cancel")
        okbutton.connect("clicked", self.ok_button_clicked, None)
        cancelbutton.connect("clicked", self.cancel_button_clicked, None)
        layout.put(okbutton,220,150);
        layout.put(cancelbutton,10,150);

        self.resize(250,200);
        self.add(layout)
        self.show_all()

    def ok_button_clicked(self, widget, data=None):
        correct = True
        network = self.network_entry.get_text()
        match = a = re.match("^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)",network)
        if match == None or len(match.groups()) != 5:
            correct = False
        else:
            for i in range(0,4):
                if int(match.groups()[i]) < 0 or int(match.groups()[i]) > 255:
                    correct = False
            if int(match.groups()[4]) < 0 or int(match.groups()[4]) > 32:
                correct = False
        if correct:
            if (self.ziter !=None):
                self.cfg.zones.modify(self.ziter, self.name_entry.get_text(), self.network_entry.get_text())
            else:
                self.cfg.zones.add(self.zid, self.name_entry.get_text(),self.network_entry.get_text())
            self.destroy()
        else:
            dialog = gtk.MessageDialog(self, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, "Invalid network!")
            dialog.run()
            dialog.destroy()

    def cancel_button_clicked(self, widget, data=None):
        self.destroy()
        
class MainWindow(gtk.Window):


    def __init__(self,cfg):
        gtk.Window.__init__(self)
        self.cfg = cfg
        self.cfg.refresh_liststore()
        self.treeview = gtk.TreeView(cfg.liststore)
        self.zoneview = gtk.TreeView(self.cfg.zones.zonestore)

        main_box = gtk.VBox(False,0)

        notebook = gtk.Notebook()

        rule_box = gtk.VBox(False, 0)

        create_cell(self.treeview, "Program", 0)
        create_cell(self.treeview, "Direction", 2, self.direction_renderer_func)
        
        create_cell(self.treeview, "Pid", 1, self.pid_renderer_func)
        create_cell(self.treeview, "Verdict", 3, self.verdict_renderer_func)
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
        rule_commit = gtk.Button("Commit!")
        rule_delete = gtk.Button("Delete")

        rulebuttons.pack_start(rule_add)
        rulebuttons.pack_start(rule_edit)
        rulebuttons.pack_start(rule_delete)
        rulebuttons.pack_start(rule_commit)
        rulebuttons.set_size_request(-1, 50);

        rule_box.pack_start(self.treeview)
        rule_box.pack_start(rulebuttons,0,0)

        rule_edit.connect("clicked", self.rule_edit_clicked, None)
        rule_add.connect("clicked", self.rule_add_clicked, None)
        rule_delete.connect("clicked", self.rule_delete_clicked, None)
        rule_commit.connect("clicked", self.rule_commit_clicked, None)

        zonebuttons = gtk.HBox(False, 0)
        
        zone_commit_button = gtk.Button("Commit!")
        zone_edit_button = gtk.Button("Edit zone...")
        zone_add_button = gtk.Button("Add zone...")
        zone_delete_button = gtk.Button("Delete zone")

        zonebuttons.pack_start(zone_add_button)
        zonebuttons.pack_start(zone_edit_button)
        zonebuttons.pack_start(zone_delete_button)
        zonebuttons.pack_start(zone_commit_button)
        zonebuttons.set_size_request(-1,50)

        zone_box = gtk.VBox(False,0)

        zone_box.pack_start(self.zoneview)
        zone_box.pack_end(zonebuttons,0,0)

        notebook.append_page(rule_box,gtk.Label('Rules'))
        notebook.append_page(zone_box,gtk.Label('Zones'))

        zone_add_button.connect("clicked", self.zone_add_clicked, None)
        zone_edit_button.connect("clicked", self.zone_edit_clicked, None)
        zone_commit_button.connect("clicked", self.zone_commit_clicked, None)
        zone_delete_button.connect("clicked", self.zone_delete_clicked, None)

        menubar = self.create_menu()
        menubar.show()

        main_box.pack_start(menubar, False, False, 2)
        main_box.pack_start(notebook)

        self.add(main_box)
        self.show_all()


    def create_menu(self):
        menu_bar = gtk.MenuBar()
        file_menu = gtk.Menu()
        quit_item = gtk.MenuItem("Quit")
        export_rule_item = gtk.MenuItem("Export rules...");
        file_menu.append(export_rule_item)
        file_menu.append(quit_item)
        quit_item.connect_object("activate", self.destroy, "file.quit")
        quit_item.show()
        export_rule_item.connect("activate", self.export_rule_clicked)
        export_rule_item.show()
        file_item = gtk.MenuItem("File")
        file_item.show()
        file_item.set_submenu(file_menu)
        menu_bar.append(file_item)
        return menu_bar    

    def export_rule_clicked(self, widget, data = None):
        chooser = gtk.FileChooserDialog(title=None,action=gtk.FILE_CHOOSER_ACTION_SAVE, buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_SAVE,gtk.RESPONSE_OK))
        chooser.set_default_response(gtk.RESPONSE_OK)
        response = chooser.run()
        if response == gtk.RESPONSE_OK:
            self.cfg.export_rules(chooser.get_filename())
        chooser.destroy()



    def direction_renderer_func(self, column, cell_renderer, tree_model, titer, userdata = None):
        val = tree_model.get_value(titer, 2)
        if (val == 0):
            cell_renderer.set_property('text', "Outbound")
        else:
            cell_renderer.set_property('text', "Inbound")


    def verdict_renderer_func(self, column, cell_renderer, tree_mode, titer, userdata = None):
        val = tree_mode.get_value(titer, 3)
        cell_renderer.set_property('text', verdict_dir[val])


    def pid_renderer_func(self, column, cell_renderer, tree_model, titer, userdata = None):
        val = tree_model.get_value(titer, 1)
        if (val == 0):
            cell_renderer.set_property('text', "*")
        else:
            cell_renderer.set_property('text', "%s" % val)


    def zone_commit_clicked(self, widget, data = None):
        data_send = self.cfg.zones.serialize()
        debug("Zones packed: data='%r'" % data_send)
        data = send_command("SZN"+data_send);

    def zone_edit_clicked(self, widget, data = None):
        (model, ziter) = self.zoneview.get_selection().get_selected()
        if (ziter == None):
            debug("No selection")
            return
        win = ZoneEditWindow(ziter,self.cfg)
        win.show()

    def zone_delete_clicked(self,widget, data = None):
        (model, ziter) = self.zoneview.get_selection().get_selected()
        if (ziter == None):
            return
        zonename = self.cfg.zones.get_name(ziter)
        dialog = gtk.MessageDialog(self, 0, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Are you sure you want to delete zone %s?" % zonename)
        response = dialog.run()
        dialog.destroy()
        if (response == gtk.RESPONSE_OK):
            self.cfg.zones.delete(ziter)            

    def rule_add_clicked(self, widget, data = None):
        win = RuleEditWindow(None, self.cfg)
        win.set_title("Add rule")
        win.show()

    def rule_edit_clicked(self, widget, data = None):
        (model, riter) = self.treeview.get_selection().get_selected()
        if (riter == None):
            debug("No selection")
            return
        win = RuleEditWindow(riter, self.cfg)
        win.set_title("Edit rule")
        win.show()

    def rule_delete_clicked(self, widget, data = None):
        (model, riter) = self.treeview.get_selection().get_selected()
        rulestore = self.cfg.liststore
        self.rule = Rule(rulestore.get_value(riter, 0), rulestore.get_value(riter, 1),rulestore.get_value(riter, 2),rulestore.get_value(riter, 3),rulestore.get_value(riter, 4),rulestore.get_value(riter, 5),rulestore.get_value(riter, 6), rulestore.get_value(riter, 7))
        self.cfg.change_store.append(("DELETE", self.rule))
        self.cfg.refresh_liststore()

    def rule_commit_clicked(self, widget, data = None):
        data = phx_serialize_changes(self.cfg.change_store)
        debug("Data serialized; data='%r'" % data)
        send_command("SET"+data)

    def zone_add_clicked(self, widget, data = None):
        win = ZoneEditWindow(None,self.cfg)
        win.show()

    def destroy(self, widget, data = None):
        gtk.main_quit();
        return False
    
def main():
    global options
    parser = OptionParser()
    parser.add_option("-s", "--socket", dest="socket_file", help="Daemon socket to connect", metavar="FILE")
    parser.add_option("-d", "--debug", dest="need_debug", action="store_true", default=False, help="Enabling debug mode")
    (options, args) = parser.parse_args()

    cfg = Config()
    data = send_command("GZN");
    cfg.zones = Zones()
    cfg.zones.parse(data)
    data = send_command("GET");
    cfg.apptable = Apptable()
    cfg.apptable.parse(data, cfg.zones.zones)
    window = MainWindow(cfg)
    gtk.main()
#    cfg.export_list_store("kakukk.txt")    

main()
