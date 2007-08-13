INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libnm-util

BUILT_SOURCES = \
	nm-access-point-bindings.h \
	nm-client-bindings.h \
	nm-device-bindings.h \
	nm-device-802-3-ethernet-bindings.h \
	nm-device-802-11-wireless-bindings.h \
	nm-marshal.h \
	nm-marshal.c \
	nm-settings-connection-glue.h \
	nm-settings-glue.h

lib_LTLIBRARIES = libnm_glib.la

libnm_glib_la_CFLAGS = 		\
	$(GLIB_CFLAGS)		\
	$(GTHREAD_CFLAGS)	\
	$(DBUS_CFLAGS)		\
	$(GCONF_CFLAGS)		\
	$(GNOME_KEYRING_CFLAGS)

libnmincludedir = $(includedir)/libnm-glib

libnminclude_HEADERS = \
	libnm_glib.h		\
	nm-object.h		\
	nm-client.h		\
	nm-device.h		\
	nm-device-802-3-ethernet.h \
	nm-device-802-11-wireless.h \
	nm-access-point.h \
	nm-ip4-config.h \
	nm-settings.h \
	nm-vpn-connection.h

libnm_glib_la_SOURCES = \
	libnm_glib.c		\
	nm-object.c		\
	nm-client.c		\
	nm-device.c		\
	nm-device-private.h	\
	nm-device-802-3-ethernet.c \
	nm-device-802-11-wireless.c \
	nm-access-point.c	\
	nm-ip4-config.c		\
	nm-settings.c		\
	nm-vpn-connection.c	\
	nm-marshal-main.c

libnm_glib_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la	\
	$(GLIB_LIBS)					\
	$(GTHREAD_LIBS)					\
	$(DBUS_LIBS)					\
	$(GCONF_LIBS)					\
	$(GNOME_KEYRING_LIBS)

noinst_PROGRAMS = libnm-glib-test

libnm_glib_test_SOURCES = libnm-glib-test.c
libnm_glib_test_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_test_LDADD = libnm_glib.la $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)

nm-marshal.h: Makefile.am nm-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_marshal $(srcdir)/nm-marshal.list --header > \
	xgen-gmh \
	&& (cmp -s xgen-gmh nm-marshal.h || cp xgen-gmh nm-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-marshal.c: Makefile.am nm-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_marshal $(srcdir)/nm-marshal.list --body > \
	xgen-gmc \
	&& cp xgen-gmc nm-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-marshal-main.c: nm-marshal.c nm-marshal.h

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

nm-settings-glue.h: $(top_srcdir)/introspection/nm-settings.xml
	dbus-binding-tool --prefix=nm_settings --mode=glib-server --output=nm-settings-glue.h $(top_srcdir)/introspection/nm-settings.xml

nm-settings-connection-glue.h: $(top_srcdir)/introspection/nm-settings-connection.xml
	dbus-binding-tool --prefix=nm_connection_settings --mode=glib-server --output=nm-settings-connection-glue.h $(top_srcdir)/introspection/nm-settings-connection.xml

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm_glib.pc

DISTCLEANFILES = libnm_glib.pc

EXTRA_DIST = libnm_glib.pc.in nm-marshal.list

CLEANFILES = \
	$(BUILT_SOURCES)
