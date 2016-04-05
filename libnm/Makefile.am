include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

SUBDIRS = . tests

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_builddir)/introspection \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/libnm \
	-I$(top_builddir)/libnm \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DNMRUNDIR=\"$(nmrundir)\" \
	$(CODE_COVERAGE_CFLAGS)

include $(top_srcdir)/libnm-core/Makefile.libnm-core

# libnm

lib_LTLIBRARIES = libnm.la

libnmincludedir = $(includedir)/libnm

libnminclude_hfiles =			\
	$(top_builddir)/shared/nm-version-macros.h \
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
	nm-device-ip-tunnel.h		\
	nm-device-macvlan.h		\
	nm-device-modem.h		\
	nm-device-olpc-mesh.h		\
	nm-device-team.h		\
	nm-device-tun.h			\
	nm-device-vlan.h		\
	nm-device-vxlan.h		\
	nm-device-wifi.h		\
	nm-device-wimax.h		\
	nm-device.h			\
	nm-dhcp-config.h		\
	nm-enum-types.h			\
	nm-ip-config.h			\
	nm-object.h			\
	nm-remote-connection.h		\
	nm-types.h			\
	nm-vpn-connection.h		\
	nm-vpn-editor.h		\
	nm-wimax-nsp.h

libnminclude_nointrospect_hfiles =	\
	nm-secret-agent-old.h		\
	nm-vpn-plugin-old.h         \
	nm-vpn-service-plugin.h

libnminclude_HEADERS =			\
	$(libnminclude_hfiles)		\
	$(libnminclude_nointrospect_hfiles)

libnm_la_private_headers =		\
	nm-dbus-helpers.h		\
	nm-device-private.h		\
	nm-dhcp4-config.h		\
	nm-dhcp6-config.h		\
	nm-ip4-config.h			\
	nm-ip6-config.h			\
	nm-manager.h			\
	nm-object-cache.h		\
	nm-object-private.h		\
	nm-remote-connection-private.h	\
	nm-remote-settings.h

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
	nm-device-ip-tunnel.c		\
	nm-device-macvlan.c		\
	nm-device-modem.c		\
	nm-device-olpc-mesh.c		\
	nm-device-team.c		\
	nm-device-tun.c			\
	nm-device-vlan.c		\
	nm-device-vxlan.c		\
	nm-device-wifi.c		\
	nm-device-wimax.c		\
	nm-device.c			\
	nm-dhcp-config.c		\
	nm-dhcp4-config.c		\
	nm-dhcp6-config.c		\
	nm-enum-types.c			\
	nm-ip-config.c			\
	nm-ip4-config.c			\
	nm-ip6-config.c			\
	nm-manager.c			\
	nm-object-cache.c		\
	nm-object.c			\
	nm-remote-connection.c		\
	nm-remote-settings.c		\
	nm-secret-agent-old.c		\
	nm-vpn-connection.c		\
	nm-vpn-plugin-old.c		\
	nm-vpn-editor.c		\
	nm-vpn-service-plugin.c     \
	nm-wimax-nsp.c

libnm_la_SOURCES =			\
	$(libnm_la_csources)		\
	$(libnm_la_private_headers)

GLIB_GENERATED = nm-enum-types.h nm-enum-types.c
nm_enum_types_sources = $(libnminclude_HEADERS)
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include <nm-core-enum-types.h>\n'
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM --fhead '\#include "nm-default.h"\n'

libnm_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(top_builddir)/introspection/libnmdbus.la \
	$(GLIB_LIBS) \
	$(UUID_LIBS) \
	$(GUDEV_LIBS)

libnm_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS)

SYMBOL_VIS_FILE=$(srcdir)/libnm.ver

libnm_la_LDFLAGS = -Wl,--version-script=$(SYMBOL_VIS_FILE) \
	-version-info "1:0:1"

###

BUILT_SOURCES = $(GLIB_GENERATED)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm.pc

DISTCLEANFILES = libnm.pc

EXTRA_DIST = libnm.pc.in libnm.ver

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
	$(libnminclude_hfiles)			\
	$(libnm_core_sources)			\
	$(libnm_la_csources)

NM-1.0.gir: libnm.la
NM_1_0_gir_INCLUDES = Gio-2.0
NM_1_0_gir_PACKAGES = gio-2.0 gudev-1.0
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

if BUILD_SETTING_DOCS

noinst_DATA = \
	nm-property-docs.xml \
	nm-setting-docs-overrides.xml \
	nm-setting-docs.xml \
	nm-keyfile-docs.xml \
	nm-ifcfg-rh-docs.xml

docs_sources = $(filter-out %/nm-core-enum-types.c,$(libnm_core_sources))

nm-setting-docs-overrides.xml: generate-plugin-docs.pl $(docs_sources)
	$(srcdir)/generate-plugin-docs.pl dbus $(top_srcdir)/libnm-core $@

nm-property-docs.xml: generate-setting-docs.py $(docs_sources) | NM-1.0.gir NM-1.0.typelib libnm.la
	export GI_TYPELIB_PATH=$(abs_builddir)$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}; \
	export LD_LIBRARY_PATH=$(abs_builddir)/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}; \
	$(srcdir)/generate-setting-docs.py \
		--gir $(builddir)/NM-1.0.gir \
		--output $@

nm-setting-docs.xml: generate-setting-docs.py $(docs_sources) nm-setting-docs-overrides.xml | NM-1.0.gir NM-1.0.typelib libnm.la
	export GI_TYPELIB_PATH=$(abs_builddir)$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}; \
	export LD_LIBRARY_PATH=$(abs_builddir)/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}; \
	$(srcdir)/generate-setting-docs.py \
		--gir $(builddir)/NM-1.0.gir \
		--overrides $(builddir)/nm-setting-docs-overrides.xml \
		--output $@

nm-keyfile-docs.xml: generate-plugin-docs.pl $(docs_sources)
	$(srcdir)/generate-plugin-docs.pl keyfile $(top_srcdir)/libnm-core $@
nm-ifcfg-rh-docs.xml: generate-plugin-docs.pl $(docs_sources)
	$(srcdir)/generate-plugin-docs.pl ifcfg-rh $(top_srcdir)/libnm-core $@

CLEANFILES += $(noinst_DATA)
EXTRA_DIST += $(noinst_DATA)

endif

EXTRA_DIST += generate-setting-docs.py generate-plugin-docs.pl
