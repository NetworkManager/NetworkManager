SUBDIRS = src auth-dialog properties po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-vpnc-service.name

EXTRA_DIST = $(nmvpnservice_DATA) $(dbusservice_DATA) 

CLEANFILES = *~
