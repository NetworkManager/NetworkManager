include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/src/devices \
	-I${top_srcdir}/src/settings \
	-I${top_srcdir}/src/platform \
	-I${top_builddir}/introspection \
	-I${top_srcdir}/shared \
	-I$(top_builddir)/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-wwan"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	$(MM_GLIB_CFLAGS)

BUILT_SOURCES = $(null)

pkglib_LTLIBRARIES = libnm-wwan.la libnm-device-plugin-wwan.la

###########################################################

GLIB_GENERATED = nm-modem-enum-types.h nm-modem-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_modem_enum_types_sources = $(srcdir)/nm-modem.h

BUILT_SOURCES += $(GLIB_GENERATED)

libnm_wwan_la_SOURCES = \
	nm-modem-broadband.c \
	nm-modem-broadband.h \
	nm-modem-manager.c \
	nm-modem-manager.h \
	nm-modem.c \
	nm-modem.h \
	\
	$(GLIB_GENERATED)

WWAN_SYMBOL_VIS_FILE=$(srcdir)/wwan-exports.ver

libnm_wwan_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(WWAN_SYMBOL_VIS_FILE)
libnm_wwan_la_LIBADD = \
	$(top_builddir)/introspection/libnmdbus.la \
	$(GLIB_LIBS) \
	$(MM_GLIB_LIBS)

###########################################################

SYMBOL_VIS_FILE=$(srcdir)/exports.ver

libnm_device_plugin_wwan_la_SOURCES = \
	nm-wwan-factory.c \
	nm-wwan-factory.h \
	nm-device-modem.c \
	nm-device-modem.h

libnm_device_plugin_wwan_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script=$(SYMBOL_VIS_FILE)

libnm_device_plugin_wwan_la_LIBADD = \
	$(top_builddir)/introspection/libnmdbus.la \
	libnm-wwan.la \
	$(GLIB_LIBS)

###########################################################

CLEANFILES = $(BUILT_SOURCES)
EXTRA_DIST = $(SYMBOL_VIS_FILE) $(WWAN_SYMBOL_VIS_FILE)

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-device-plugin-wwan.so $(SYMBOL_VIS_FILE)
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-wwan.so $(WWAN_SYMBOL_VIS_FILE)

endif

