#! /usr/bin/python
import pygtk; pygtk.require("2.0")
import gtk
import gtk.gdk

try:
    import trayicon
    from NetworkManager import NetworkManager
except:
    print "type 'make' make the necessary modules to run this example"
    import sys
    sys.exit(1)


class network_tray:

    def __init__(self):
        self._make_menu()
        self._make_tray()
        
        self._nm = NetworkManager()
        for signal in self._nm.NM_SIGNALS:
            self._nm.nm_object.connect_to_signal(signal,
                                                 self._network_event)

        self._network_event(None, None, None,None,None)
        
    def _add_separator_item(self):
        self._menu.append(gtk.SeparatorMenuItem())

    def _add_label_item(self, label):
        menuitem = gtk.MenuItem()
        menuitem.set_sensitive(gtk.FALSE)
        gtklabel = gtk.Label()

        gtklabel.set_markup("<span size=\"small\" foreground=\"#aaaaaa\" weight=\"ultralight\">%s</span>" % label)
        gtklabel.set_selectable(gtk.FALSE)
        hbox = gtk.HBox(homogeneous=gtk.TRUE, spacing=6)
        hbox.pack_end(gtklabel,expand=gtk.TRUE, fill=gtk.TRUE, padding=0)
        menuitem.add(hbox)
        self._menu.append(menuitem)
        menuitem.show_all()

    def _add_other_wireless_item(self):
        menuitem = gtk.MenuItem()
        menuitem.set_sensitive(gtk.TRUE)
        gtklabel = gtk.Label()
        gtklabel.set_alignment(0,0)
        gtklabel.set_label("Other Wireless Networks...")
        hbox = gtk.HBox(homogeneous=gtk.TRUE, spacing=6)
        hbox.pack_end(gtklabel,expand=gtk.TRUE, fill=gtk.TRUE, padding=6)
        menuitem.add(hbox) 
        tt = "Add a wireless network that does not appear on the list"
        self._tooltips.set_tip(menuitem,tt)       
        self._menu.append(menuitem)
        menuitem.show_all()

    def _add_device_menu_item(self, device):
        if not self._is_wireless(device):
            menuitem = gtk.RadioMenuItem(group=self.__radio_group)
            if self._is_active(device):
                menuitem.set_active(1)
        else:
            menuitem = gtk.MenuItem()
        
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        hbox.pack_start(self._get_icon(device), expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        label = gtk.Label()
        label.set_justify(gtk.JUSTIFY_LEFT)
        label.set_text(self._get_device_name(device))
        hbox.pack_start(label, expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        menuitem.add(hbox)        
        hbox.show()
        self._menu.append(menuitem)
        tt = "IP: %d\nProduct Name: %s\nVendor: %s\nDevice Name: %s" % (device["nm.ip4"], device["pci.product"], device["info.vendor"], device["nm.name"] )
        self._tooltips.set_tip(menuitem,tt)
        menuitem.show_all()
        
    def _add_network_menu_item(self, device, network, active_network):
        menuitem = gtk.RadioMenuItem(group=self.__radio_group)
        menuitem.set_right_justified(gtk.FALSE)
        if active_network == gtk.TRUE:
            menuitem.set_active(1)
            
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        menuitem.add(hbox)
        label = gtk.Label(network["name"])
        label.set_alignment(0.1,0.5)
        label.show()
        hbox.pack_start(label,expand=gtk.TRUE, fill=gtk.TRUE)
        progress = gtk.ProgressBar()
        progress.set_orientation(gtk.PROGRESS_LEFT_TO_RIGHT)
        q = self._get_quality(device, network)
        progress.set_fraction(q)
#        progress.set_text("%s %%" % int(q*100))
        progress.show()
        hbox.pack_start(progress, expand=gtk.FALSE, fill=gtk.FALSE)
        icon = self._get_encrypted_icon()
        if network["encrypted"] == 1:
            icon.hide()
            hbox.pack_start(icon,expand=gtk.FALSE, fill=gtk.FALSE)
        else:
            icon.show()

        hbox.show()
        self._menu.append(menuitem)
        tt = "Name: %s\nEncrypted: %d\nRate: %d\nFrequency: %f\nAddress: %s\nQuality: %d" % (network['name'], network['encrypted'], network['rate'],network['frequency'], network['address'], network['quality'])
        self._tooltips.set_tip(menuitem,tt)
        menuitem.show()

    def _get_quality(self, device, network):
        if network["quality"] == 0:
            proc = "/proc/driver/aironet/%s/BSSList" % device["net.interface"]
            import fileinput
            for line in fileinput.input(proc):
                dev_info = line.split()
                if network["name"] in dev_info:
                    fileinput.close()
                    try:
                        qual =  float(dev_info[4])
                        q =  float(qual / 100)
                        return q
                    except ValueError:
                        return 0.0
            fileinput.close()
        else:
            return float(network["quality"])
        return 0.0

    def _get_device_name(self, device):
        if self._is_wireless(device):
            if self._nm.number_wireless_devices() > 1:
                return device["info.product"]
            else:
                return "Wireless Network"
        else:
            if self._nm.number_wired_devices() > 1:
                return device["info.product"]
            else:
                return "Wired Network"            
        
    def _is_wireless(self,dev):
        if dev["nm.type"] == self._nm.WIRELESS_DEVICE:
            return gtk.TRUE
        return gtk.FALSE

    def _is_active(self, dev):
        return dev["nm.status"] != self._nm.DISCONNECTED

    def _number_wired_devices(self, devices):
        return self._number_x_devices(devices, self._nm.WIRED_DEVICE)
    
    def _number_wireless_devices(self, devices):
        return self._number_x_devices(devices, self._nm.WIRELESS_DEVICE)
        
    def _network_event(self, interface, signal_name,
                       service, path, message):

        for child in self._menu.get_children():
            self._menu.remove(child)
        
        devices = self._nm.get_devices()
        active_device = self._nm.get_active_device()
        tt = ""

        def sort_networks(x, y):
            if x["name"] > y["name"]:
                print y["name"], x["name"]            
                return 1
            print x["name"] ,y["name"]            
            return -1
        
        wireless = gtk.FALSE
        for device in devices:

            if self._is_wireless(device) and wireless == gtk.FALSE:
                wireless = gtk.TRUE
                self._add_separator_item()
                self._add_label_item("Wireless Networks")
            else:
                self._add_device_menu_item(device)
            tt = "%s%s [%s]\n"%(tt,device["info.product"],device["nm.status"])

            self._tooltips.set_tip(self._top_level_menu,tt)

            if self._is_wireless(device):
                device["nm.networks"].values().sort(sort_networks)
                print device["nm.networks"]
                for name, network in device["nm.networks"].iteritems():
                    try: 
                        if device["nm.active_network"] == name:
                            active_network = gtk.TRUE
                        else:
                            active_network = gtk.FALSE
                    except:
                        active_network = gtk.FALSE
                    self._add_network_menu_item(device,network,active_network)

        if wireless == gtk.TRUE:
            self._add_other_wireless_item()
            
        self._current_icon = self._get_icon(active_device)

        self._current_icon.show()
        self._top_level_menu.show()

    def _get_encrypted_icon(self):
        pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/keyring.png")
        pb = pb.scale_simple(24,24,gtk.gdk.INTERP_NEAREST)
        _keyring = gtk.Image()
        _keyring.set_from_pixbuf(pb)
        return _keyring
        
    def _get_icon(self, active_device):

        if active_device:
            if active_device["nm.type"] == self._nm.WIRED_DEVICE:
                pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/wired.png")
                pb = pb.scale_simple(24,24,gtk.gdk.INTERP_NEAREST)
                _wired_icon = gtk.Image()
                _wired_icon.set_from_pixbuf(pb)
                return _wired_icon                
            elif active_device["nm.type"] == self._nm.WIRELESS_DEVICE:
                pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/wireless-applet.png")
                pb = pb.scale_simple(24,24,gtk.gdk.INTERP_NEAREST)
                _wireless_icon = gtk.Image()
                _wireless_icon.set_from_pixbuf(pb)
                return _wireless_icon                
        else:
            pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/wireless-applet.png")
            pb = pb.scale_simple(16,16,gtk.gdk.INTERP_NEAREST)
            _nothing_icon = gtk.Image()
            _nothing_icon.set_from_pixbuf(pb)
            return _nothing_icon            

        
    def _make_tray(self):
        self._tray = trayicon.TrayIcon("NetworkManager")

        self._tooltips = gtk.Tooltips()
        tooltip = "Getting Network Information"        
        self._tooltips.set_tip(self._menu,tooltip)

        self._tray.add(self._menu_bar)
        self._tray.show()

    def _make_menu(self):
        self._menu_bar = gtk.MenuBar()        

        self._top_level_menu = gtk.MenuItem()
        self._menu_bar.append(self._top_level_menu)

        self._menu = gtk.Menu()
        self._top_level_menu.set_submenu(self._menu)

        self._current_icon = self._get_icon(None)
        self._current_icon.show()
        
        self._top_level_menu.add(self._current_icon)
        self._menu_bar.show()
        self._top_level_menu.show()
        self._menu.show()

        self.__radio_group = gtk.RadioMenuItem()


if __name__ == "__main__":
    nt = network_tray()
    gtk.main()
