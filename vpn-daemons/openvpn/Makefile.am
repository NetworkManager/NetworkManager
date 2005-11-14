AUTOMAKE_OPTIONS = foreign

SUBDIRS = src auth-dialog properties po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openvpn-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-openvpn-service.name

desktopdir = $(datadir)/applications
desktop_in_files = nm-openvpn.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

icondir = $(datadir)/icons/hicolor/48x48/apps
icon_DATA = gnome-mime-application-x-openvpn-settings.png

EXTRA_DIST = $(nmvpnservice_DATA) \
             $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update
