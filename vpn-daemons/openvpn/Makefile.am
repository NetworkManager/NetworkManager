AUTOMAKE_OPTIONS = foreign

if WITH_GNOME
SUBDIRS = src auth-dialog properties po
else
SUBDIRS = src
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openvpn-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-openvpn-service.name

if WITH_GNOME
desktopdir = $(datadir)/applications
desktop_in_files = nm-openvpn.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

icondir = $(datadir)/icons/hicolor/48x48/apps
icon_DATA = gnome-mime-application-x-openvpn-settings.png
endif

nm-openvpn-service.name: $(srcdir)/nm-openvpn-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

EXTRA_DIST = nm-openvpn-service.name.in \
             $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update
