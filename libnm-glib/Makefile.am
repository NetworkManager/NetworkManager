INCLUDES = -I$(top_srcdir)/include

BUILT_SOURCES = \
	nm-client-bindings.h \
	nm-device-bindings.h \
	nm-device-802-3-ethernet-bindings.h \
	nm-device-802-11-wireless-bindings.h \
	nm-access-point-bindings.h

lib_LTLIBRARIES = libnm-glib.la

libnm_glib_la_CPPFLAGS = \
	$(GLIB_CFLAGS)	\
	$(DBUS_CFLAGS)

libnmincludedir = $(includedir)/libnm-glib

libnminclude_HEADERS = \
	nm-client.h		\
	nm-device.h		\
	nm-device-802-3-ethernet.h \
	nm-device-802-11-wireless.h \
	nm-access-point.h

libnm_glib_la_SOURCES = \
	nm-client.c		\
	nm-device.c		\
	nm-device-private.h	\
	nm-device-802-3-ethernet.c \
	nm-device-802-11-wireless.c \
	nm-access-point.c	\
	nm-utils.c		\
	nm-utils.h		\
	$(BUILT_SOURCES)

libnm_glib_la_LDFLAGS = $(GLIB_LIBS) $(DBUS_LIBS)

noinst_PROGRAMS = libnm-glib-test

AM_CPPFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)

libnm_glib_test_SOURCES = libnm-glib-test.c
libnm_glib_test_LDADD = $(GLIB_LIBS) $(DBUS_LIBS) $(top_builddir)/libnm-glib/libnm-glib.la

nm-client-bindings.h: $(top_srcdir)/introspection/nm-manager.xml
	dbus-binding-tool --prefix=nm_client --mode=glib-client --output=nm-client-bindings.h $(top_srcdir)/introspection/nm-manager.xml

nm-device-bindings.h: $(top_srcdir)/introspection/nm-device.xml
	dbus-binding-tool --prefix=nm_device --mode=glib-client --output=nm-device-bindings.h $(top_srcdir)/introspection/nm-device.xml

nm-device-802-3-ethernet-bindings.h: $(top_srcdir)/introspection/nm-device-802-3-ethernet.xml
	dbus-binding-tool --prefix=nm_device_802_3_ethernet --mode=glib-client --output=nm-device-802-3-ethernet-bindings.h $(top_srcdir)/introspection/nm-device-802-3-ethernet.xml

nm-device-802-11-wireless-bindings.h: $(top_srcdir)/introspection/nm-device-802-11-wireless.xml
	dbus-binding-tool --prefix=nm_device_802_11_wireless --mode=glib-client --output=nm-device-802-11-wireless-bindings.h $(top_srcdir)/introspection/nm-device-802-11-wireless.xml

nm-access-point-bindings.h: $(top_srcdir)/introspection/nm-access-point.xml
	dbus-binding-tool --prefix=nm_access_point --mode=glib-client --output=nm-access-point-bindings.h $(top_srcdir)/introspection/nm-access-point.xml


pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-glib.pc

DISTCLEANFILES = libnm-glib.pc

EXTRA_DIST = libnm-glib.pc.in

CLEANFILES = \
	$(BUILT_SOURCES)
