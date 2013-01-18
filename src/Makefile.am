SUBDIRS= \
	generated \
	logging \
	posix-signals \
	dns-manager \
	vpn-manager \
	dhcp-manager \
	ip6-manager \
	supplicant-manager \
	ppp-manager \
	dnsmasq-manager \
	modem-manager \
	bluez-manager \
	firewall-manager \
	wifi \
	settings

if WITH_WIMAX
SUBDIRS += wimax
endif

SUBDIRS += . tests

INCLUDES = -I${top_srcdir} \
           -I${top_builddir}/include \
           -I${top_srcdir}/include \
           -I${top_builddir}/src/generated \
           -I${top_srcdir}/src/generated \
           -I${top_srcdir}/src/logging \
           -I${top_srcdir}/src/posix-signals \
           -I${top_srcdir}/src/dns-manager \
           -I${top_srcdir}/src/vpn-manager \
           -I${top_srcdir}/src/dhcp-manager \
           -I${top_srcdir}/src/ip6-manager \
           -I${top_srcdir}/src/supplicant-manager \
           -I${top_srcdir}/src/dnsmasq-manager \
           -I${top_srcdir}/src/modem-manager \
           -I$(top_srcdir)/src/bluez-manager \
           -I$(top_srcdir)/src/firewall-manager \
           -I$(top_srcdir)/src/settings \
           -I$(top_srcdir)/src/wifi \
           -I${top_srcdir}/libnm-util \
           -I${top_builddir}/libnm-util \
           -I${top_srcdir}/callouts

###########################################
# Test libraries
###########################################

noinst_LTLIBRARIES = \
	libtest-dhcp.la \
	libtest-policy-hosts.la \
	libtest-wifi-ap-utils.la

###########################################
# DHCP test library
###########################################

libtest_dhcp_la_SOURCES = \
	nm-ip4-config.c \
	nm-ip6-config.c \
	nm-hostname-provider.c \
	nm-dbus-manager.c

libtest_dhcp_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(LIBNL_CFLAGS)

libtest_dhcp_la_LIBADD = \
	$(top_builddir)/src/generated/libnm-generated.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(LIBNL_LIBS)

###########################################
# Hosts policy test library
###########################################

libtest_policy_hosts_la_SOURCES = \
	nm-policy-hosts.c \
	nm-policy-hosts.h

libtest_policy_hosts_la_CPPFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(GLIB_CFLAGS)

libtest_policy_hosts_la_LIBADD = \
	${top_builddir}/src/logging/libnm-logging.la \
	$(GLIB_LIBS)


###########################################
# Wifi ap utils
###########################################

libtest_wifi_ap_utils_la_SOURCES = \
	nm-wifi-ap-utils.c \
	nm-wifi-ap-utils.h

libtest_wifi_ap_utils_la_CPPFLAGS = \
	$(GLIB_CFLAGS)

libtest_wifi_ap_utils_la_LIBADD = \
	${top_builddir}/libnm-util/libnm-util.la \
	$(GLIB_LIBS)


###########################################
# NetworkManager
###########################################

sbin_PROGRAMS = NetworkManager

NetworkManager_SOURCES = \
		nm-types.h \
		nm-call-store.c \
		nm-call-store.h \
		nm-device.c \
		nm-device.h \
		nm-device-private.h \
		nm-device-ethernet.c \
		nm-device-ethernet.h \
		nm-device-adsl.c \
		nm-device-adsl.h \
		nm-device-wifi.c \
		nm-device-wifi.h \
		nm-device-wired.c \
		nm-device-wired.h \
		nm-device-olpc-mesh.c	\
		nm-device-olpc-mesh.h	\
		nm-device-bt.c \
		nm-device-bt.h \
		nm-device-modem.h \
		nm-device-modem.c \
		nm-device-infiniband.c \
		nm-device-infiniband.h \
		nm-device-bond.c \
		nm-device-bond.h \
		nm-device-bridge.c \
		nm-device-bridge.h \
		nm-device-vlan.c \
		nm-device-vlan.h \
		nm-wifi-ap.c \
		nm-wifi-ap.h \
		nm-wifi-ap-utils.c \
		nm-wifi-ap-utils.h \
		nm-dbus-manager.h \
		nm-dbus-manager.c \
		nm-udev-manager.c \
		nm-udev-manager.h \
		nm-device-factory.h \
		nm-hostname-provider.c \
		nm-hostname-provider.h \
		nm-ip4-config.c \
		nm-ip4-config.h \
		nm-ip6-config.c \
		nm-ip6-config.h \
		nm-active-connection.h \
		nm-active-connection.c \
		nm-config.h \
		nm-config.c \
		main.c \
		nm-policy.c \
		nm-policy.h \
		nm-policy-hosts.c \
		nm-policy-hosts.h \
		nm-policy-hostname.c \
		nm-policy-hostname.h \
		NetworkManagerUtils.c \
		NetworkManagerUtils.h \
		nm-system.c \
		nm-system.h \
		nm-manager.c \
		nm-manager.h \
		nm-manager-auth.c \
		nm-manager-auth.h \
		nm-netlink-monitor.c \
		nm-netlink-monitor.h \
		nm-netlink-utils.c \
		nm-netlink-utils.h \
		nm-netlink-compat.h \
		nm-netlink-compat.c \
		nm-activation-request.c \
		nm-activation-request.h \
		nm-properties-changed-signal.c \
		nm-properties-changed-signal.h \
		nm-dhcp4-config.c \
		nm-dhcp4-config.h \
		nm-dhcp6-config.c \
		nm-dhcp6-config.h \
		nm-rfkill.h \
		nm-session-monitor.h \
		nm-session-utils.c \
		nm-session-utils.h \
		nm-sleep-monitor.h \
		nm-connection-provider.h \
		nm-connection-provider.c \
		nm-dispatcher.c \
		nm-dispatcher.h

if WITH_CONCHECK
NetworkManager_SOURCES += nm-connectivity.c nm-connectivity.h
endif

if SESSION_TRACKING_SYSTEMD
NetworkManager_SOURCES += nm-session-monitor-systemd.c
else
if SESSION_TRACKING_CK
NetworkManager_SOURCES += nm-session-monitor-ck.c
else
NetworkManager_SOURCES += nm-session-monitor-null.c
endif
endif

if SUSPEND_RESUME_SYSTEMD
NetworkManager_SOURCES += nm-sleep-monitor-systemd.c
else
# UPower suspend/resume used whenever systemd is not enabled
NetworkManager_SOURCES += nm-sleep-monitor-upower.c
endif

nm-access-point-glue.h: $(top_srcdir)/introspection/nm-access-point.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_access_point --mode=glib-server --output=$@ $<

nm-manager-glue.h: $(top_srcdir)/introspection/nm-manager.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_manager --mode=glib-server --output=$@ $<

nm-device-interface-glue.h: $(top_srcdir)/introspection/nm-device.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_interface --mode=glib-server --output=$@ $<

nm-device-ethernet-glue.h: $(top_srcdir)/introspection/nm-device-ethernet.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_ethernet --mode=glib-server --output=$@ $<

nm-device-infiniband-glue.h: $(top_srcdir)/introspection/nm-device-infiniband.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_infiniband --mode=glib-server --output=$@ $<

nm-device-adsl-glue.h: $(top_srcdir)/introspection/nm-device-adsl.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_adsl --mode=glib-server --output=$@ $<

nm-device-wifi-glue.h: $(top_srcdir)/introspection/nm-device-wifi.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_wifi --mode=glib-server --output=$@ $<

nm-device-bt-glue.h: $(top_srcdir)/introspection/nm-device-bt.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_bt --mode=glib-server --output=$@ $<

nm-device-olpc-mesh-glue.h: $(top_srcdir)/introspection/nm-device-olpc-mesh.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_olpc_mesh --mode=glib-server --output=$@ $<

nm-device-bond-glue.h: $(top_srcdir)/introspection/nm-device-bond.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_bond --mode=glib-server --output=$@ $<

nm-device-bridge-glue.h: $(top_srcdir)/introspection/nm-device-bridge.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_bridge --mode=glib-server --output=$@ $<

nm-device-vlan-glue.h: $(top_srcdir)/introspection/nm-device-vlan.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_vlan --mode=glib-server --output=$@ $<

nm-ip4-config-glue.h: $(top_srcdir)/introspection/nm-ip4-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_ip4_config --mode=glib-server --output=$@ $<

nm-ip6-config-glue.h: $(top_srcdir)/introspection/nm-ip6-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_ip6_config --mode=glib-server --output=$@ $<

nm-active-connection-glue.h: $(top_srcdir)/introspection/nm-active-connection.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_active_connection --mode=glib-server --output=$@ $<

nm-dhcp4-config-glue.h: $(top_srcdir)/introspection/nm-dhcp4-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_dhcp4_config --mode=glib-server --output=$@ $<

nm-dhcp6-config-glue.h: $(top_srcdir)/introspection/nm-dhcp6-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_dhcp6_config --mode=glib-server --output=$@ $<

nm-device-modem-glue.h: $(top_srcdir)/introspection/nm-device-modem.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_modem --mode=glib-server --output=$@ $<

BUILT_SOURCES = \
	nm-access-point-glue.h \
	nm-manager-glue.h \
	nm-device-interface-glue.h \
	nm-device-ethernet-glue.h \
	nm-device-infiniband-glue.h \
	nm-device-bond-glue.h \
	nm-device-bridge-glue.h \
	nm-device-vlan-glue.h \
	nm-device-adsl-glue.h \
	nm-device-wifi-glue.h \
	nm-device-olpc-mesh-glue.h \
	nm-device-bt-glue.h \
	nm-device-modem-glue.h \
	nm-ip4-config-glue.h \
	nm-ip6-config-glue.h \
	nm-active-connection-glue.h \
	nm-dhcp4-config-glue.h \
	nm-dhcp6-config-glue.h

NetworkManager_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(SYSTEMD_LOGIN_CFLAGS) \
	-DBINDIR=\"$(bindir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\" \
	-DNMPLUGINDIR=\"$(pkglibdir)\" \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMRUNDIR=\"$(nmrundir)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\" \
	-DARP_DEBUG

if WITH_CONCHECK
NetworkManager_CPPFLAGS += $(LIBSOUP_CFLAGS)
endif

if SESSION_TRACKING_CK
NetworkManager_CPPFLAGS += -DCKDB_PATH=\"${CKDB_PATH}\"
endif

NetworkManager_LDADD = \
	./generated/libnm-generated.la \
	./logging/libnm-logging.la \
	./posix-signals/libnm-posix-signals.la \
	./dns-manager/libdns-manager.la \
	./vpn-manager/libvpn-manager.la \
	./dhcp-manager/libdhcp-manager.la \
	./ip6-manager/libip6-manager.la \
	./supplicant-manager/libsupplicant-manager.la \
	./dnsmasq-manager/libdnsmasq-manager.la \
	./ppp-manager/libppp-manager.la \
	./modem-manager/libmodem-manager.la \
	./bluez-manager/libbluez-manager.la \
	./wifi/libwifi-utils.la \
	./firewall-manager/libfirewall-manager.la \
	./settings/libsettings.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(POLKIT_LIBS) \
	$(SYSTEMD_LOGIN_LIBS) \
	$(LIBM) \
	$(LIBDL)

if WITH_CONCHECK
NetworkManager_LDADD += $(LIBSOUP_LIBS)
endif

NetworkManager_LDFLAGS = -rdynamic

NetworkManagerdir = $(datadir)/NetworkManager
NetworkManager_DATA = gdb-cmd

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = org.freedesktop.NetworkManager.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(NetworkManager_DATA)

rundir=$(localstatedir)/run/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager
install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(rundir)
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(statedir)
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(pkglibdir)

CLEANFILES = $(BUILT_SOURCES)

