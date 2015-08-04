include $(GLIB_MAKEFILE)

SUBDIRS = . tests

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-DG_LOG_DOMAIN=\""libnm-glib"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

BUILT_SOURCES = \
	nm-vpn-plugin-glue.h \
	nm-secret-agent-glue.h


noinst_LTLIBRARIES = \
	libdeprecated-nm-glib.la

#####################################################
# Deprecated original libnm_glib bits
#####################################################

libdeprecated_nm_glib_la_SOURCES = \
	libnm_glib.h \
	libnm_glib.c

libdeprecated_nm_glib_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
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
	$(GUDEV_CFLAGS) \
	-DNMRUNDIR=\"$(nmrundir)\"

libnmincludedir = $(includedir)/libnm-glib
libnmvpndir = $(includedir)/libnm-glib

libnminclude_HEADERS = \
	nm-object.h \
	nm-client.h \
	nm-device.h \
	nm-device-ethernet.h \
	nm-device-infiniband.h \
	nm-device-adsl.h \
	nm-device-wifi.h \
	nm-device-bt.h \
	nm-device-olpc-mesh.h \
	nm-device-bond.h \
	nm-device-team.h \
	nm-device-bridge.h \
	nm-device-vlan.h \
	nm-device-generic.h \
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
	nm-wimax-nsp.h \
	nm-glib-enum-types.h

libnmvpn_HEADERS = \
	nm-vpn-plugin.h \
	nm-vpn-plugin-ui-interface.h \
	nm-vpn-plugin-utils.h \
	nm-vpn-enum-types.h

libnm_glib_la_csources = \
	nm-object.c \
	nm-dbus-helpers.c \
	nm-client.c \
	nm-device.c \
	nm-device-ethernet.c \
	nm-device-infiniband.c \
	nm-device-adsl.c \
	nm-device-wifi.c \
	nm-device-bt.c \
	nm-device-olpc-mesh.c \
	nm-device-bond.c \
	nm-device-team.c \
	nm-device-bridge.c \
	nm-device-vlan.c \
	nm-device-generic.c \
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
	nm-wimax-nsp.c \
	nm-glib-enum-types.c

libnm_glib_la_private_headers = \
	nm-object-private.h \
	nm-device-private.h \
	nm-types-private.h \
	nm-object-cache.h \
	nm-remote-connection-private.h \
	nm-dbus-helpers-private.h

libnm_glib_la_SOURCES = \
	$(libnm_glib_la_csources) \
	$(libnm_glib_la_private_headers)

GLIB_GENERATED = nm-glib-enum-types.h nm-glib-enum-types.c
nm_glib_enum_types_sources = $(libnminclude_HEADERS)
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

libnm_glib_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(builddir)/libdeprecated-nm-glib.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

SYMBOL_VIS_FILE=$(srcdir)/libnm-glib.ver

libnm_glib_la_LDFLAGS = -Wl,--version-script=$(SYMBOL_VIS_FILE) \
	-version-info "13:0:9"

noinst_PROGRAMS = libnm-glib-test

libnm_glib_test_SOURCES = libnm-glib-test.c
libnm_glib_test_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_test_LDADD = libnm-glib.la $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)


libnm_glib_vpn_la_SOURCES = \
	nm-vpn-plugin.c \
	nm-vpn-plugin-ui-interface.c \
	nm-vpn-plugin-utils.c \
	nm-vpn-enum-types.c
GLIB_GENERATED += nm-vpn-enum-types.h nm-vpn-enum-types.c
nm_vpn_enum_types_sources = $(libnmvpn_HEADERS)
libnm_glib_vpn_la_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_vpn_la_LIBADD = $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)
libnm_glib_vpn_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnm-glib-vpn.ver \
	-version-info "3:0:2"

BUILT_SOURCES += $(GLIB_GENERATED)

#####################################################

nm-vpn-plugin-glue.h: $(top_srcdir)/introspection/nm-vpn-plugin.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_vpn_plugin --mode=glib-server --output=$@ $<

nm-secret-agent-glue.h: $(top_srcdir)/introspection/nm-secret-agent.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_secret_agent --mode=glib-server --output=$@ $<

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-glib.pc libnm-glib-vpn.pc

DISTCLEANFILES = libnm-glib.pc libnm-glib.pc

EXTRA_DIST = libnm-glib.pc.in libnm-glib-vpn.pc.in libnm-glib.ver libnm-glib-vpn.ver

CLEANFILES = $(BUILT_SOURCES)

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_COMPILER_ARGS = --includedir=$(top_builddir)/libnm-util

if HAVE_INTROSPECTION
introspection_sources = $(libnminclude_HEADERS) $(libnm_glib_la_csources)

NMClient-1.0.gir: libnm-glib.la
NMClient_1_0_gir_INCLUDES = Gio-2.0 DBusGLib-1.0
NMClient_1_0_gir_PACKAGES = gio-2.0 dbus-glib-1 gudev-1.0
NMClient_1_0_gir_EXPORT_PACKAGES = libnm-glib libnm-glib-vpn
NMClient_1_0_gir_CFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/libnm-glib -I$(top_srcdir)/libnm-util
NMClient_1_0_gir_LIBS = libnm-glib.la $(top_builddir)/libnm-util/libnm-util.la
NMClient_1_0_gir_FILES = $(introspection_sources)
NMClient_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm --include-uninstalled=$(top_builddir)/libnm-util/NetworkManager-1.0.gir
INTROSPECTION_GIRS += NMClient-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-glib.so $(SYMBOL_VIS_FILE)

endif

