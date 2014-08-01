include $(GLIB_MAKEFILE)

SUBDIRS = . tests

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/libnm \
	-I$(top_builddir)/libnm \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE

include $(top_srcdir)/libnm-core/Makefile.libnm-core

# libnm

lib_LTLIBRARIES = libnm.la

libnm_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DNMRUNDIR=\"$(nmrundir)\"

libnmincludedir = $(includedir)/libnm

libnminclude_HEADERS =			\
	NetworkManager.h		\
	nm-access-point.h		\
	nm-active-connection.h		\
	nm-client.h			\
	nm-device-adsl.h		\
	nm-device-bond.h		\
	nm-device-bridge.h		\
	nm-device-bt.h			\
	nm-device-ethernet.h		\
	nm-device-generic.h		\
	nm-device-infiniband.h		\
	nm-device-modem.h		\
	nm-device-olpc-mesh.h		\
	nm-device-team.h		\
	nm-device-vlan.h		\
	nm-device-wifi.h		\
	nm-device-wimax.h		\
	nm-device.h			\
	nm-dhcp4-config.h		\
	nm-dhcp6-config.h		\
	nm-enum-types.h			\
	nm-ip4-config.h			\
	nm-ip6-config.h			\
	nm-object.h			\
	nm-remote-connection.h		\
	nm-remote-settings.h		\
	nm-secret-agent.h		\
	nm-types.h			\
	nm-vpn-connection.h		\
	nm-wimax-nsp.h

libnm_la_private_headers =		\
	nm-dbus-helpers-private.h	\
	nm-device-private.h		\
	nm-object-cache.h		\
	nm-object-private.h		\
	nm-remote-connection-private.h	\
	nm-types-private.h

libnm_la_csources =			\
	nm-access-point.c		\
	nm-active-connection.c		\
	nm-client.c			\
	nm-dbus-helpers.c		\
	nm-device-adsl.c		\
	nm-device-bond.c		\
	nm-device-bridge.c		\
	nm-device-bt.c			\
	nm-device-ethernet.c		\
	nm-device-generic.c		\
	nm-device-infiniband.c		\
	nm-device-modem.c		\
	nm-device-olpc-mesh.c		\
	nm-device-team.c		\
	nm-device-vlan.c		\
	nm-device-wifi.c		\
	nm-device-wimax.c		\
	nm-device.c			\
	nm-dhcp4-config.c		\
	nm-dhcp6-config.c		\
	nm-enum-types.c			\
	nm-ip4-config.c			\
	nm-ip6-config.c			\
	nm-object-cache.c		\
	nm-object.c			\
	nm-remote-connection.c		\
	nm-remote-settings.c		\
	nm-secret-agent.c		\
	nm-types.c			\
	nm-vpn-connection.c		\
	nm-wimax-nsp.c

libnm_la_SOURCES =			\
	$(libnm_la_csources)		\
	$(libnm_la_private_headers)

nm-secret-agent-glue.h: $(top_srcdir)/introspection/nm-secret-agent.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_secret_agent --mode=glib-server --output=$@ $<

GLIB_GENERATED = nm-enum-types.h nm-enum-types.c
nm_enum_types_sources = $(libnminclude_HEADERS)
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include <nm-core-enum-types.h>\n'
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

BUILT_SOURCES = \
	nm-vpn-plugin-glue.h \
	nm-secret-agent-glue.h

libnm_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(UUID_LIBS) \
	$(GUDEV_LIBS)

SYMBOL_VIS_FILE=$(srcdir)/libnm.ver

libnm_la_LDFLAGS = -Wl,--version-script=$(SYMBOL_VIS_FILE) \
	-version-info "0:0:0"


# libnm-vpn

lib_LTLIBRARIES += libnm-vpn.la

libnmvpndir = $(includedir)/libnm

libnmvpn_HEADERS =			\
	nm-vpn-plugin.h			\
	nm-vpn-plugin-ui-interface.h	\
	nm-vpn-plugin-utils.h		\
	nm-vpn-enum-types.h

libnm_vpn_la_SOURCES = \
	nm-vpn-plugin.c \
	nm-vpn-plugin-ui-interface.c \
	nm-vpn-plugin-utils.c \
	nm-vpn-enum-types.c

nm-vpn-plugin-glue.h: $(top_srcdir)/introspection/nm-vpn-plugin.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_vpn_plugin --mode=glib-server --output=$@ $<

GLIB_GENERATED += nm-vpn-enum-types.h nm-vpn-enum-types.c
nm_vpn_enum_types_sources = $(libnmvpn_HEADERS)
libnm_vpn_la_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_vpn_la_LIBADD = $(GLIB_LIBS) $(DBUS_LIBS)
libnm_vpn_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnm-vpn.ver \
	-version-info "0:0:0"

###

BUILT_SOURCES += $(GLIB_GENERATED)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm.pc libnm-vpn.pc

DISTCLEANFILES = libnm.pc libnm-vpn.pc

EXTRA_DIST = libnm.pc.in libnm-vpn.pc.in libnm.ver libnm-vpn.ver

CLEANFILES = $(BUILT_SOURCES)

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_COMPILER_ARGS =			\
	--includedir=$(top_srcdir)/libnm-core	\
	--includedir=$(top_builddir)/libnm-core	\
	--includedir=$(top_srcdir)/libnm	\
	--includedir=$(top_builddir)/libnm

if HAVE_INTROSPECTION
introspection_sources =				\
	$(libnm_core_headers)			\
	$(libnminclude_HEADERS)			\
	$(libnm_core_sources)			\
	$(libnm_la_csources)

NM-1.0.gir: libnm.la
NM_1_0_gir_INCLUDES = Gio-2.0 DBusGLib-1.0
NM_1_0_gir_PACKAGES = gio-2.0 dbus-glib-1 gudev-1.0
NM_1_0_gir_EXPORT_PACKAGES = libnm
NM_1_0_gir_CFLAGS = $(AM_CPPFLAGS)
NM_1_0_gir_LIBS = libnm.la
NM_1_0_gir_FILES = $(introspection_sources)
NM_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm
INTROSPECTION_GIRS += NM-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm.so $(SYMBOL_VIS_FILE)
