#! /usr/bin/python
import pygtk; pygtk.require("2.0")
import gtk
import gtk.gdk

try:
    import trayicon
    from NetworkManager import NetworkManager
except ImportError, e:
    print e
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

    def _wired_network_cb(self, menuitem, event, device_name):
        return
        print menuitem, event, device_name
        try:
            self._nm.nm_object.setActiveDevice(device_name)
        except Exception, e:
            print e
        
    def _wireless_network_cb(self, menuitem, event, device_name, network_name):
        return
        print menuitem, event, device_name, network_name
        try:
            self._nm.nm_object.setActiveDevice(device_name, network_name)
        except Exception, e:
            print e
        
    def _add_separator_item(self):
        sep = gtk.SeparatorMenuItem()
        sep.show()
        self._menu.append(sep)

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

    def _add_wired_device_menu_item(self, device):
        menuitem = gtk.RadioMenuItem(group=self.__radio_group)
        if self._is_active(device):
            menuitem.set_active(1)

        menuitem.connect("button-press-event",self._wired_network_cb,
                         device["nm.device"])
        
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        hbox.pack_start(self._get_icon(device), expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        label = gtk.Label()
        label.set_justify(gtk.JUSTIFY_LEFT)
        label.set_text(self._get_device_name(device))
        hbox.pack_start(label, expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        menuitem.add(hbox)        
        hbox.show()
        self._menu.append(menuitem)
        try:
            tt = "IP: %d\nProduct Name: %s\nVendor: %s\nDevice Name: %s" % (device["nm.ip4"], device["pci.product"], device["info.vendor"], device["nm.name"] )
            self._tooltips.set_tip(menuitem,tt)
        except:
            pass
        menuitem.show_all()

    def _add_wireless_device_menu_item(self, device, generic=gtk.FALSE):
        menuitem = gtk.MenuItem()

        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        hbox.pack_start(self._get_icon(device), expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        label = gtk.Label()
        label.set_justify(gtk.JUSTIFY_LEFT)
        label.set_markup("<span foreground=\"#aaaaaa\">%s</span>" % self._get_device_name(device))
        label.set_selectable(gtk.FALSE)        
        hbox.pack_start(label, expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        menuitem.add(hbox)
        hbox.show()
        self._menu.append(menuitem)
        try:
            tt = "IP: %d\nProduct Name: %s\nVendor: %s\nDevice Name: %s" % (device["nm.ip4"], device["pci.product"], device["info.vendor"], device["nm.name"] )
            self._tooltips.set_tip(menuitem,tt)
        except:
            pass
        menuitem.show_all()

    def _add_vpn_menu_item(self):
        menuitem = gtk.CheckMenuItem()
        
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        hbox.pack_start(self._get_vpn_icon(), expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        label = gtk.Label()
        label.set_justify(gtk.JUSTIFY_LEFT)
        label.set_text("Virtual Private Network")
        hbox.pack_start(label, expand=gtk.FALSE, fill=gtk.FALSE, padding=6)
        menuitem.add(hbox)        
        hbox.show()
        self._menu.append(menuitem)
        tt = "Use a Virtual Private Network to securely connect to your companies internal system"
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
        strength = float(network["strength"] * .01)
        progress.set_fraction(strength)
#        progress.set_text("%s%%" % int(strength*100))
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
        tt = "Name: %s\nEncrypted: %d\nRate: %d\nFrequency: %f\nAddress: %s\nStrength: %1.2f" % (network['name'], network['encrypted'], network['rate'],network['frequency'], network['address'], strength)
        self._tooltips.set_tip(menuitem,tt)
        menuitem.connect("button-press-event", self._wireless_network_cb,
                         device["nm.device"], network["network"])
        menuitem.show()

    def _get_device_name(self, device):

        if self._is_wireless(device):
            try:
                if self._nm.number_wireless_devices() > 1:
                    return device["pci.subsys_vendor"]
                else:
                    return "Wireless Network"
            except:
                return "Wireless PCMCIA Card"
        else:
            try:
                if self._nm.number_wired_devices() > 1:
                    return device["info.product"]
            except:
                pass
            return "Wired Network"
        
    def _is_wireless(self,dev):
        if dev["nm.type"] == self._nm.WIRELESS_DEVICE:
            return gtk.TRUE
        return gtk.FALSE

    def _is_active(self, dev):
        try:
            if dev["nm.link_active"] == 1:
                return gtk.TRUE
        except:
            return gtk.FALSE

    def _network_event(self, interface, signal_name,
                       service, path, message):

        for child in self._menu.get_children():
            self._menu.remove(child)
        
        devices = self._nm.get_devices()
        active_device = self._nm.get_active_device()

        def sort_devs(x, y):
            if x["nm.type"] > y["nm.type"]:
                return 1
            elif x["nm.type"] < y["nm.type"]:
                return -1
            elif x["nm.link_active"] > y["nm.link_active"]:
                return 1
            elif x["nm.link_active"] < y["nm.link_active"]:
                return -1
            return 0

        def sort_networks(x, y):
            if x.lower() < y.lower():
                return 1
            return -1

        type = 0
        devices.sort(sort_devs)
        for device in devices:
            
            if self._is_wireless(device):
                type = device["nm.type"]
                if self._nm.number_wireless_devices() > 1:
                    self._add_wireless_device_menu_item(device)
                else:
                    self._add_wireless_device_menu_item(device, gtk.FALSE)

                device["nm.networks"].keys().sort(sort_networks)
                for name, network in device["nm.networks"].iteritems():
                    try: 
                        if device["nm.active_network"] == name:
                            active_network = gtk.TRUE
                        else:
                            active_network = gtk.FALSE
                    except:
                        active_network = gtk.FALSE
                    self._add_network_menu_item(device,network,active_network)
                
            else:
                if type == self._nm.WIRELESS_DEVICE:
                    self._add_separator_item()
                self._add_wired_device_menu_item(device)


        self._add_other_wireless_item()
#        self._add_vpn_menu_item()
        
        self._current_icon = self._get_icon(active_device)

        self._current_icon.show()
        self._top_level_menu.show()

    def _get_encrypted_icon(self):
        pb = gtk.gdk.pixbuf_new_from_file("/usr/share/icons/hicolor/16x16/stock/generic/stock_keyring.png")
        pb = pb.scale_simple(16,16,gtk.gdk.INTERP_NEAREST)
        _keyring = gtk.Image()
        _keyring.set_from_pixbuf(pb)
        return _keyring

    def _get_vpn_icon(self):
        return self._get_encrypted_icon()
    
    def _get_icon(self, active_device):

        if active_device:
            if active_device["nm.type"] == self._nm.WIRED_DEVICE:
                pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/icons/nm-device-wired.png")
                pb = pb.scale_simple(16,16,gtk.gdk.INTERP_NEAREST)
                _wired_icon = gtk.Image()
                _wired_icon.set_from_pixbuf(pb)
                return _wired_icon                
            elif active_device["nm.type"] == self._nm.WIRELESS_DEVICE:
                pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/icons/nm-device-wireless.png")
                pb = pb.scale_simple(16,16,gtk.gdk.INTERP_NEAREST)
                _wireless_icon = gtk.Image()
                _wireless_icon.set_from_pixbuf(pb)
                return _wireless_icon                
        else:
            pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/icons/nm-device-wireless.png")
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
