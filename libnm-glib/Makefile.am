SUBDIRS=. tests

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/marshallers

BUILT_SOURCES = \
	nm-access-point-bindings.h \
	nm-client-bindings.h \
	nm-device-bindings.h \
	nm-device-ethernet-bindings.h \
	nm-device-wifi-bindings.h \
	nm-device-bt-bindings.h \
	nm-settings-connection-bindings.h \
	nm-device-wimax-bindings.h \
	nm-device-modem-bindings.h \
	nm-settings-bindings.h \
	nm-vpn-connection-bindings.h \
	nm-vpn-plugin-glue.h \
	nm-active-connection-bindings.h \
	nm-ip4-config-bindings.h \
	nm-dhcp4-config-bindings.h \
	nm-ip6-config-bindings.h \
	nm-dhcp6-config-bindings.h \
	nm-secret-agent-glue.h


noinst_LTLIBRARIES = \
	libdeprecated-nm-glib.la \
	libnm-glib-test.la

#####################################################
# Deprecated original libnm_glib bits
#####################################################

libdeprecated_nm_glib_la_SOURCES = \
	libnm_glib.h \
	libnm_glib.c

libdeprecated_nm_glib_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-Wno-deprecated-declarations \
	-Wno-deprecated

libdeprecated_nm_glib_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

libdeprecateddir = $(includedir)/libnm-glib
libdeprecated_HEADERS = libnm_glib.h

#####################################################
# Real libnm-glib stuff
#####################################################

lib_LTLIBRARIES = libnm-glib.la libnm-glib-vpn.la

libnm_glib_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GUDEV_CFLAGS)

libnmincludedir = $(includedir)/libnm-glib
libnmvpndir = $(includedir)/libnm-glib

libnminclude_HEADERS = \
	nm-object.h \
	nm-client.h \
	nm-device.h \
	nm-device-ethernet.h \
	nm-device-wifi.h \
	nm-device-bt.h \
	nm-access-point.h \
	nm-ip4-config.h \
	nm-device-modem.h \
	nm-vpn-connection.h \
	nm-types.h \
	nm-active-connection.h \
	nm-dhcp4-config.h \
	nm-ip6-config.h \
	nm-dhcp6-config.h \
	nm-remote-connection.h \
	nm-remote-settings.h \
	nm-secret-agent.h \
	nm-device-wimax.h \
	nm-wimax-nsp.h

libnmvpn_HEADERS = \
	nm-vpn-plugin.h \
	nm-vpn-plugin-ui-interface.h \
	nm-vpn-plugin-utils.h

libnm_glib_la_csources = \
	nm-object.c \
	nm-client.c \
	nm-dbus-utils.c \
	nm-device.c \
	nm-device-ethernet.c \
	nm-device-wifi.c \
	nm-device-bt.c \
	nm-access-point.c \
	nm-ip4-config.c \
	nm-device-modem.c \
	nm-vpn-connection.c \
	nm-types.c \
	nm-object-cache.c \
	nm-active-connection.c \
	nm-dhcp4-config.c \
	nm-ip6-config.c \
	nm-dhcp6-config.c \
	nm-remote-connection.c \
	nm-remote-settings.c \
	nm-secret-agent.c \
	nm-device-wimax.c \
	nm-wimax-nsp.c

libnm_glib_la_private_headers = \
	nm-object-private.h \
	nm-dbus-utils.h \
	nm-device-private.h \
	nm-types-private.h \
	nm-object-cache.h \
	nm-remote-connection-private.h

libnm_glib_la_SOURCES = \
	$(libnm_glib_la_csources) \
	$(libnm_glib_la_private_headers)

libnm_glib_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(builddir)/libdeprecated-nm-glib.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

SYMBOL_VIS_FILE=$(srcdir)/libnm-glib.ver

libnm_glib_la_LDFLAGS = -Wl,--version-script=$(SYMBOL_VIS_FILE) \
	-version-info "5:0:1"

noinst_PROGRAMS = libnm-glib-test

libnm_glib_test_SOURCES = libnm-glib-test.c
libnm_glib_test_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_test_LDADD = libnm-glib.la $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)


libnm_glib_vpn_la_SOURCES = \
	nm-vpn-plugin.c \
	nm-vpn-plugin-ui-interface.c \
	nm-vpn-plugin-utils.c
libnm_glib_vpn_la_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_vpn_la_LIBADD = $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)
libnm_glib_vpn_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnm-glib-vpn.ver \
	-version-info "2:0:1"

#####################################################
# Test libnm-glib stuff
#####################################################

libnm_glib_test_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DLIBNM_GLIB_TEST

libnm_glib_test_la_SOURCES = \
	$(libnminclude_HEADERS) \
	$(libnm_glib_la_SOURCES)

libnm_glib_test_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

#####################################################

nm-client-bindings.h: $(top_srcdir)/introspection/nm-manager.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_client --mode=glib-client --output=$@ $<

nm-device-bindings.h: $(top_srcdir)/introspection/nm-device.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device --mode=glib-client --output=$@ $<

nm-device-ethernet-bindings.h: $(top_srcdir)/introspection/nm-device-ethernet.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_ethernet --mode=glib-client --output=$@ $<

nm-device-wifi-bindings.h: $(top_srcdir)/introspection/nm-device-wifi.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_wifi --mode=glib-client --output=$@ $<

nm-device-bt-bindings.h: $(top_srcdir)/introspection/nm-device-bt.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_device_bt --mode=glib-client --output=$@ $<

nm-access-point-bindings.h: $(top_srcdir)/introspection/nm-access-point.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_access_point --mode=glib-client --output=$@ $<

nm-settings-bindings.h: $(top_srcdir)/introspection/nm-settings.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_settings --mode=glib-client --output=$@ $<

nm-settings-connection-bindings.h: $(top_srcdir)/introspection/nm-settings-connection.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_settings_connection --mode=glib-client --output=$@ $<

nm-vpn-connection-bindings.h: $(top_srcdir)/introspection/nm-vpn-connection.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_vpn_connection --mode=glib-client --output=$@ $<

nm-vpn-plugin-glue.h: $(top_srcdir)/introspection/nm-vpn-plugin.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_vpn_plugin --mode=glib-server --output=$@ $<

nm-active-connection-bindings.h: $(top_srcdir)/introspection/nm-active-connection.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_active_connection --mode=glib-client --output=$@ $<

nm-ip4-config-bindings.h: $(top_srcdir)/introspection/nm-ip4-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_ip4_config --mode=glib-client --output=$@ $<

nm-dhcp4-config-bindings.h: $(top_srcdir)/introspection/nm-dhcp4-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_dhcp4_config --mode=glib-client --output=$@ $<

nm-ip6-config-bindings.h: $(top_srcdir)/introspection/nm-ip6-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_ip6_config --mode=glib-client --output=$@ $<

nm-dhcp6-config-bindings.h: $(top_srcdir)/introspection/nm-dhcp6-config.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_dhcp6_config --mode=glib-client --output=$@ $<

nm-secret-agent-glue.h: $(top_srcdir)/introspection/nm-secret-agent.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_secret_agent --mode=glib-server --output=$@ $<

nm-device-wimax-bindings.h: $(top_srcdir)/introspection/nm-device-wimax.xml
	dbus-binding-tool --prefix=nm_device_wimax --mode=glib-client --output=$@ $<

nm-device-modem-bindings.h: $(top_srcdir)/introspection/nm-device-modem.xml
	dbus-binding-tool --prefix=nm_device_modem --mode=glib-client --output=$@ $<

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-glib.pc libnm-glib-vpn.pc

DISTCLEANFILES = libnm-glib.pc libnm-glib.pc

EXTRA_DIST = libnm-glib.pc.in libnm-glib-vpn.pc.in libnm-glib.ver libnm-glib-vpn.ver

CLEANFILES = $(BUILT_SOURCES) *-bindings.h *-glue.h

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_COMPILER_ARGS = --includedir=$(top_builddir)/libnm-util

if HAVE_INTROSPECTION
introspection_sources = $(libnminclude_HEADERS) $(libnm_glib_la_csources)

NMClient-1.0.gir: libnm-glib.la
NMClient_1_0_gir_INCLUDES = GObject-2.0 DBusGLib-1.0
NMClient_1_0_gir_PACKAGES = gobject-2.0 dbus-glib-1 gudev-1.0
NMClient_1_0_gir_CFLAGS = $(INCLUDES) -I$(top_srcdir)/libnm-glib -I$(top_srcdir)/libnm-util
NMClient_1_0_gir_LIBS = libnm-glib.la
NMClient_1_0_gir_FILES = $(introspection_sources)
NMClient_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm_ --include-uninstalled=$(top_builddir)/libnm-util/NetworkManager-1.0.gir
INTROSPECTION_GIRS += NMClient-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

if WITH_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-glib.so $(SYMBOL_VIS_FILE)

endif

