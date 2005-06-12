SUBDIRS = src auth-dialog properties po

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-vpnc-service.name

EXTRA_DIST = $(dbusservice_DATA) $(nmvpnservice_DATA)

CLEANFILES = *~
