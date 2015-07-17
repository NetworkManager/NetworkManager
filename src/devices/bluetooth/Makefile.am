include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/src/devices \
	-I${top_srcdir}/src/settings \
	-I${top_srcdir}/src/platform \
	-I${top_srcdir}/src/devices/wwan \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-bluetooth"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(DBUS_CFLAGS)

GLIB_GENERATED = nm-bt-enum-types.h nm-bt-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_bt_enum_types_sources = $(srcdir)/nm-bt-error.h

nm-device-bt-glue.h: $(top_srcdir)/introspection/nm-device-bt.xml
	dbus-binding-tool --prefix=nm_device_bt --mode=glib-server --output=$@ $<

BUILT_SOURCES = $(GLIB_GENERATED) nm-device-bt-glue.h

pkglib_LTLIBRARIES = libnm-device-plugin-bluetooth.la

SYMBOL_VIS_FILE=$(srcdir)/exports.ver

libnm_device_plugin_bluetooth_la_SOURCES = \
	nm-bluez-manager.c \
	nm-bluez-manager.h \
	nm-bluez-common.h \
	nm-bluez-device.c \
	nm-bluez-device.h \
	nm-bluez4-adapter.c \
	nm-bluez4-adapter.h \
	nm-bluez4-manager.c \
	nm-bluez4-manager.h \
	nm-bluez5-manager.c \
	nm-bluez5-manager.h \
	nm-bt-error.h \
	nm-bt-error.c \
	\
	nm-device-bt.c \
	nm-device-bt.h \
	\
	$(BUILT_SOURCES)

libnm_device_plugin_bluetooth_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script=$(SYMBOL_VIS_FILE)

libnm_device_plugin_bluetooth_la_LIBADD = \
	$(top_builddir)/src/devices/wwan/libnm-wwan.la \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

if WITH_BLUEZ5_DUN
AM_CPPFLAGS += $(BLUEZ5_CFLAGS)

libnm_device_plugin_bluetooth_la_SOURCES += \
	nm-bluez5-dun.c \
	nm-bluez5-dun.h

libnm_device_plugin_bluetooth_la_LIBADD += $(BLUEZ5_LIBS)
endif

CLEANFILES = $(BUILT_SOURCES)
EXTRA_DIST = $(SYMBOL_VIS_FILE)

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-device-plugin-bluetooth.so $(SYMBOL_VIS_FILE)

endif

