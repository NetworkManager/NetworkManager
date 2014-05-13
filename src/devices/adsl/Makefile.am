include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/devices \
	-I${top_srcdir}/src/settings \
	-I${top_srcdir}/src/platform \
	-I${top_srcdir}/src/ppp-manager \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-util \
	-DG_LOG_DOMAIN=\""NetworkManager-adsl"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(DBUS_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(GUDEV_CFLAGS)

GLIB_GENERATED = nm-adsl-enum-types.h nm-adsl-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_adsl_enum_types_sources = $(srcdir)/nm-device-adsl.h

nm-device-adsl-glue.h: $(top_srcdir)/introspection/nm-device-adsl.xml
	dbus-binding-tool --prefix=nm_device_adsl --mode=glib-server --output=$@ $<

BUILT_SOURCES = $(GLIB_GENERATED) nm-device-adsl-glue.h

pkglib_LTLIBRARIES = libnm-device-plugin-adsl.la

SYMBOL_VIS_FILE=$(srcdir)/exports.ver

libnm_device_plugin_adsl_la_SOURCES = \
	nm-atm-manager.c \
	nm-atm-manager.h \
	nm-device-adsl.c \
	nm-device-adsl.h \
	\
	$(BUILT_SOURCES)

libnm_device_plugin_adsl_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script=$(SYMBOL_VIS_FILE)

libnm_device_plugin_adsl_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

CLEANFILES = $(BUILT_SOURCES)
EXTRA_DIST = $(SYMBOL_VIS_FILE)

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-device-plugin-adsl.so $(SYMBOL_VIS_FILE)

endif

