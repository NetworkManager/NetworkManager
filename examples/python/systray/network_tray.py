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
        menuitem.set_right_justified(gtk.TRUE)
        menuitem.set_sensitive(gtk.FALSE)
        gtklabel = gtk.Label()
        gtklabel.set_justify(gtk.JUSTIFY_RIGHT)
        gtklabel.set_markup("<span size=\"small\" foreground=\"#aaaaaa\" weight=\"ultralight\">%s</span>" % label)
        gtklabel.set_selectable(gtk.FALSE)
        hbox = gtk.HBox(homogeneous=gtk.TRUE, spacing=6)
        hbox.pack_end(gtklabel,expand=gtk.TRUE, fill=gtk.TRUE, padding=0)
        menuitem.add(hbox)
        self._menu.append(menuitem)
        menuitem.show_all()
        
    def _add_device_menu_item(self, device, active=gtk.FALSE):
        menuitem = gtk.MenuItem()
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        hbox.pack_start(self._get_icon(device), expand=gtk.FALSE, fill=gtk.FALSE)
        label = gtk.Label()
        label.set_justify(gtk.JUSTIFY_LEFT)
        if active == gtk.TRUE:
            label.set_markup("<span weight=\"bold\">%s</span>" % device["info.product"])
        else:
            label.set_text(device["info.product"])
        hbox.pack_start(label, expand=gtk.FALSE, fill=gtk.FALSE)
        menuitem.add(hbox)        
        hbox.show()
        self._menu.append(menuitem)
        menuitem.show_all()

    def _add_network_menu_item(self, network):
        menuitem = gtk.MenuItem()
        menuitem.set_right_justified(gtk.FALSE)
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=6)
        menuitem.add(hbox)
        label = gtk.Label(network["name"])
        label.set_alignment(0.1,0.5)
        label.show()
        hbox.pack_start(label,expand=gtk.TRUE, fill=gtk.TRUE)
        progress = gtk.ProgressBar()
        progress.set_fraction(network["quality"])
        progress.show()
        hbox.pack_start(progress, expand=gtk.FALSE, fill=gtk.FALSE)
        icon = self._get_encrypted_icon()
        if network["encrypted"] == 1:
            icon.hide()
        else:
            icon.show()
        hbox.pack_start(icon,expand=gtk.FALSE, fill=gtk.FALSE)
        hbox.show()
        self._menu.append(menuitem)
        menuitem.show()
        

    def _network_event(self, interface, signal_name,
                       service, path, message):

        for child in self._menu.get_children():
            self._menu.remove(child)
        
        devices = self._nm.get_devices()
        active_device = self._nm.get_active_device()
        tt = ""
        self._add_label_item("Network Connections")
        for device in devices:
            if device == active_device:
                active = gtk.TRUE
            else:
                active = gtk.FALSE

            self._add_device_menu_item(device, active)
            tt = "%s%s [%s]\n"%(tt,device["info.product"],device["nm.status"])

        self._tooltips.set_tip(self._top_level_menu,tt)

        if active_device["nm.type"] == self._nm.WIRELESS_DEVICE:
            self._add_separator_item()
            self._add_label_item("Wireless Networks")
            for name, network in active_device["nm.networks"].iteritems():
                self._add_network_menu_item(network)
                
        
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

if __name__ == "__main__":
    nt = network_tray()
    gtk.main()
