include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

if ENABLE_TESTS
SUBDIRS=. tests
endif

AM_CPPFLAGS = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/src/devices \
	-I${top_srcdir}/src/settings \
	-I${top_srcdir}/src/platform \
	-I${top_srcdir}/src/supplicant-manager \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-wifi"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(DBUS_CFLAGS)

GLIB_GENERATED = nm-wifi-enum-types.h nm-wifi-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_wifi_enum_types_sources = \
	$(srcdir)/nm-device-wifi.h \
	$(srcdir)/nm-wifi-ap.h \
	$(srcdir)/nm-device-olpc-mesh.h

glue_sources = \
	nm-device-wifi-glue.h \
	nm-device-olpc-mesh-glue.h

%-glue.h: $(top_srcdir)/introspection/%.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=$(subst -,_,$(subst -glue.h,,$@)) --mode=glib-server --output=$@ $<

BUILT_SOURCES = $(GLIB_GENERATED) $(glue_sources)

pkglib_LTLIBRARIES = libnm-device-plugin-wifi.la

libnm_device_plugin_wifi_la_SOURCES = \
	nm-wifi-factory.c \
	nm-device-wifi.c \
	nm-device-wifi.h \
	nm-wifi-ap.c \
	nm-wifi-ap.h \
	nm-wifi-ap-utils.c \
	nm-wifi-ap-utils.h \
	nm-device-olpc-mesh.c \
	nm-device-olpc-mesh.h \
	\
	$(BUILT_SOURCES)

SYMBOL_VIS_FILE=$(srcdir)/exports.ver

libnm_device_plugin_wifi_la_LDFLAGS = \
	-module -avoid-version \
	 -Wl,--version-script=$(SYMBOL_VIS_FILE)

libnm_device_plugin_wifi_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = $(SYMBOL_VIS_FILE)

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-device-plugin-wifi.so $(SYMBOL_VIS_FILE)

endif

