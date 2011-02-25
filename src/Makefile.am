SUBDIRS= \
	logging \
	dns-manager \
	vpn-manager \
	dhcp-manager \
	ip6-manager \
	supplicant-manager \
	ppp-manager \
	backends \
	dnsmasq-manager \
	modem-manager \
	bluez-manager \
	settings

if WITH_WIMAX
SUBDIRS += wimax
endif

SUBDIRS += . tests

INCLUDES = -I${top_srcdir} \
           -I${top_srcdir}/include \
           -I${top_builddir}/marshallers \
           -I${top_srcdir}/src/logging \
           -I${top_srcdir}/src/dns-manager \
           -I${top_srcdir}/src/vpn-manager \
           -I${top_srcdir}/src/dhcp-manager \
           -I${top_srcdir}/src/ip6-manager \
           -I${top_srcdir}/src/supplicant-manager \
           -I${top_srcdir}/src/dnsmasq-manager \
           -I${top_srcdir}/src/modem-manager \
           -I$(top_srcdir)/src/bluez-manager \
           -I$(top_srcdir)/src/settings \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/callouts

if WITH_WIMAX
INCLUDES += -I$(top_srcdir)/src/wimax
endif

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
	$(top_builddir)/marshallers/libmarshallers.la \
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
		nm-call-store.c \
		nm-call-store.h \
		nm-device.c \
		nm-device.h \
		nm-device-interface.c \
		nm-device-interface.h \
		nm-device-private.h \
		nm-device-ethernet.c \
		nm-device-ethernet.h \
		nm-device-wifi.c \
		nm-device-wifi.h \
		nm-device-olpc-mesh.c	\
		nm-device-olpc-mesh.h	\
		nm-device-bt.c \
		nm-device-bt.h \
		nm-device-modem.h \
		nm-device-modem.c \
		nm-wifi-ap.c \
		nm-wifi-ap.h \
		nm-wifi-ap-utils.c \
		nm-wifi-ap-utils.h \
		nm-dbus-manager.h \
		nm-dbus-manager.c \
		nm-udev-manager.c \
		nm-udev-manager.h \
		nm-hostname-provider.c \
		nm-hostname-provider.h \
		nm-ip4-config.c \
		nm-ip4-config.h \
		nm-ip6-config.c \
		nm-ip6-config.h \
		nm-active-connection.h \
		nm-active-connection.c \
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
		nm-activation-request.c \
		nm-activation-request.h \
		nm-properties-changed-signal.c \
		nm-properties-changed-signal.h \
		wpa.c \
		wpa.h \
		nm-dhcp4-config.c \
		nm-dhcp4-config.h \
		nm-dhcp6-config.c \
		nm-dhcp6-config.h \
		nm-rfkill.h \
		nm-session-monitor.c \
		nm-session-monitor.h

nm-access-point-glue.h: $(top_srcdir)/introspection/nm-access-point.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_access_point --mode=glib-server --output=$@ $<

nm-manager-glue.h: $(top_srcdir)/introspection/nm-manager.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_manager --mode=glib-server --output=$@ $<

nm-device-interface-glue.h: $(top_srcdir)/introspection/nm-device.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_interface --mode=glib-server --output=$@ $<

nm-device-ethernet-glue.h: $(top_srcdir)/introspection/nm-device-ethernet.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_ethernet --mode=glib-server --output=$@ $<

nm-device-wifi-glue.h: $(top_srcdir)/introspection/nm-device-wifi.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_wifi --mode=glib-server --output=$@ $<

nm-device-bt-glue.h: $(top_srcdir)/introspection/nm-device-bt.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_bt --mode=glib-server --output=$@ $<

nm-device-olpc-mesh-glue.h: $(top_srcdir)/introspection/nm-device-olpc-mesh.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_olpc_mesh --mode=glib-server --output=$@ $<

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
	$(GMODULE_CFLAGS) \
	$(POLKIT_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DNM_RUN_DIR=\"$(rundir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\" \
	-DARP_DEBUG


WIMAX_LIBS=
if WITH_WIMAX
WIMAX_LIBS += ./wimax/libwimax.la
endif

NetworkManager_LDADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	./logging/libnm-logging.la \
	./dns-manager/libdns-manager.la \
	./vpn-manager/libvpn-manager.la \
	./dhcp-manager/libdhcp-manager.la \
	./ip6-manager/libip6-manager.la \
	./supplicant-manager/libsupplicant-manager.la \
	./dnsmasq-manager/libdnsmasq-manager.la \
	./ppp-manager/libppp-manager.la \
	./modem-manager/libmodem-manager.la \
	./bluez-manager/libbluez-manager.la \
	./settings/libsettings.la \
	$(WIMAX_LIBS) \
	./backends/libnmbackend.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(GMODULE_LIBS) \
	$(POLKIT_LIBS) \
	$(LIBM) \
	$(LIBDL)

NetworkManager_LDFLAGS = -rdynamic

libexec_PROGRAMS = nm-crash-logger
nm_crash_logger_SOURCES = nm-crash-logger.c
nm_crash_logger_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"
nm_crash_logger_LDADD = $(GLIB_LIBS)


NetworkManagerdir = $(datadir)/NetworkManager
NetworkManager_DATA = gdb-cmd

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(NetworkManager_DATA)

rundir=$(localstatedir)/run/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager
install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(rundir)
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(statedir)

CLEANFILES = $(BUILT_SOURCES)

