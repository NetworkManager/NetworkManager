#! /usr/bin/python
import pygtk; pygtk.require("2.0")
import gtk
import gtk.gdk
import trayicon
from NetworkManager import NetworkManager


class network_tray:

    def __init__(self):
        self._make_icons()
        self._make_menu()
        self._make_tray()
        
        self._nm = NetworkManager()
        for signal in self._nm.NM_SIGNALS:
            self._nm.nm_object.connect_to_signal(signal,
                                                 self._network_event)

        self._network_event(None, None, None,None,None)
        
    def _add_separator_item(self):
        self._menu.append(gtk.SeparatorMenuItem())

    def _add_device_menu_item(self, device):
        menuitem = gtk.MenuItem()
        hbox = gtk.HBox(homogeneous=gtk.FALSE, spacing=3)
        hbox.pack_start(self._get_icon(device), expand=gtk.FALSE, fill=gtk.FALSE)
        hbox.pack_start(gtk.Label(device["info.product"]), expand=gtk.TRUE, fill=gtk.TRUE)
        menuitem.add(hbox)        
        hbox.show()
        self._menu.append(menuitem)
        menuitem.show_all()

    def _add_network_menu_item(self, network):
        menuitem = gtk.MenuItem()
        hbox = gtk.HBox()
        menuitem.add(hbox)
        hbox.add(gtk.Label("label"))
        progress = gtk.ProgressBar()
        progress.set_fraction(.5)
        hbox.add(progress)
        hbox.show()
        self._menu.append(menuitem)
        menuitem.show()
        

    def _network_event(self, interface, signal_name,
                       service, path, message):
        devices = self._nm.get_devices()
        tt = ""
        for device in devices:
            self._add_device_menu_item(device)
            tt = "%s%s [%s]\n"%(tt,device["info.product"],device["nm.status"])

        self._tooltips.set_tip(self._menu,tt)
#        self._add_separator_item()

        self._current_icon = self._get_icon(self._nm.get_active_device())

        self._current_icon.show()
        self._top_level_menu.show_all()
        
    def _get_icon(self, active_device):

        if active_device:
            if active_device["nm.type"] == self._nm.WIRED_DEVICE:
                return self._wired_icon
            elif active_device["nm.type"] == self._nm.WIRELESS_DEVICE:
                return self._wireless_icon
        else:
            return self._nothing_icon

    def _make_icons(self):
        pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/wireless-applet.png")
        pb = pb.scale_simple(16,16,gtk.gdk.INTERP_NEAREST)
        self._nothing_icon = gtk.Image()
        self._nothing_icon.set_from_pixbuf(pb)
        
        pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/wireless-applet.png")
        pb = pb.scale_simple(24,24,gtk.gdk.INTERP_NEAREST)
        self._wireless_icon = gtk.Image()
        self._wireless_icon.set_from_pixbuf(pb)
        
        pb = gtk.gdk.pixbuf_new_from_file("../../../panel-applet/wired.png")
        pb = pb.scale_simple(24,24,gtk.gdk.INTERP_NEAREST)
        self._wired_icon = gtk.Image()
        self._wired_icon.set_from_pixbuf(pb)
        
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

        self._current_icon = self._nothing_icon
        self._current_icon.show()
        
        self._top_level_menu.add(self._current_icon)
        self._menu_bar.show()
        self._top_level_menu.show()
        self._menu.show()                

if __name__ == "__main__":
    nt = network_tray()
    gtk.main()
