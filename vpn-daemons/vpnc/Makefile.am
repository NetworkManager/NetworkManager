SUBDIRS = src auth-dialog properties po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-vpnc-service.name

desktopdir = $(datadir)/applications
desktop_in_files = nm-vpnc.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

EXTRA_DIST = $(nmvpnservice_DATA) $(dbusservice_DATA) 

CLEANFILES = *~
