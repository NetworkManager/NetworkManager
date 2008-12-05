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
	nm-exported-connection-glue.h \
	nm-exported-connection-bindings.h \
	nm-settings-glue.h \
	nm-settings-bindings.h \
	nm-settings-system-bindings.h \
	nm-vpn-connection-bindings.h \
	nm-vpn-plugin-glue.h \
	nm-active-connection-bindings.h \
	nm-ip4-config-bindings.h \
	nm-dhcp4-config-bindings.h

lib_LTLIBRARIES = libnm_glib.la libnm_glib_vpn.la

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
	nm-device-ethernet.h \
	nm-device-wifi.h \
	nm-access-point.h \
	nm-ip4-config.h \
	nm-settings.h \
	nm-gsm-device.h \
	nm-cdma-device.h \
	nm-serial-device.h \
	nm-vpn-connection.h \
	nm-vpn-plugin.h \
	nm-vpn-plugin-ui-interface.h \
	nm-types.h \
	nm-active-connection.h \
	nm-dbus-connection.h \
	nm-dbus-settings.h \
	nm-dbus-settings-system.h \
	nm-dhcp4-config.h

libnm_glib_la_SOURCES = \
	libnm_glib.c		\
	nm-object.c		\
	nm-object-private.h \
	nm-client.c		\
	nm-dbus-utils.c		\
	nm-dbus-utils.h		\
	nm-device.c		\
	nm-device-private.h	\
	nm-device-ethernet.c \
	nm-device-wifi.c \
	nm-access-point.c	\
	nm-ip4-config.c		\
	nm-settings.c		\
	nm-gsm-device.c	\
	nm-cdma-device.c	\
	nm-serial-device.c \
	nm-vpn-connection.c	\
	nm-types.c \
	nm-types-private.h \
	nm-object-cache.c \
	nm-object-cache.h \
	nm-active-connection.c \
	nm-dbus-connection.c \
	nm-dbus-settings.c \
	nm-dbus-settings-system.c \
	nm-dhcp4-config.c

libnm_glib_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la	\
	$(top_builddir)/marshallers/libmarshallers.la	\
	$(GLIB_LIBS)					\
	$(GTHREAD_LIBS)					\
	$(DBUS_LIBS)					\
	$(GCONF_LIBS)					\
	$(GNOME_KEYRING_LIBS)

libnm_glib_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnm_glib.ver \
	-version-info "1:0:1"

noinst_PROGRAMS = libnm-glib-test

libnm_glib_test_SOURCES = libnm-glib-test.c
libnm_glib_test_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_test_LDADD = libnm_glib.la $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)


libnm_glib_vpn_la_SOURCES = nm-vpn-plugin.c nm-vpn-plugin-ui-interface.c
libnm_glib_vpn_la_CFLAGS = $(GLIB_CFLAGS) $(DBUS_CFLAGS)
libnm_glib_vpn_la_LIBADD = $(top_builddir)/libnm-util/libnm-util.la $(GLIB_LIBS) $(DBUS_LIBS)
libnm_glib_vpn_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnm_glib_vpn.ver \
	-version-info "0:0:0"


nm-client-bindings.h: $(top_srcdir)/introspection/nm-manager-client.xml
	dbus-binding-tool --prefix=nm_client --mode=glib-client --output=$@ $<

nm-device-bindings.h: $(top_srcdir)/introspection/nm-device.xml
	dbus-binding-tool --prefix=nm_device --mode=glib-client --output=$@ $<

nm-device-ethernet-bindings.h: $(top_srcdir)/introspection/nm-device-ethernet.xml
	dbus-binding-tool --prefix=nm_device_ethernet --mode=glib-client --output=$@ $<

nm-device-wifi-bindings.h: $(top_srcdir)/introspection/nm-device-wifi.xml
	dbus-binding-tool --prefix=nm_device_wifi --mode=glib-client --output=$@ $<

nm-access-point-bindings.h: $(top_srcdir)/introspection/nm-access-point.xml
	dbus-binding-tool --prefix=nm_access_point --mode=glib-client --output=$@ $<

nm-settings-glue.h: $(top_srcdir)/introspection/nm-settings.xml
	dbus-binding-tool --prefix=nm_settings --mode=glib-server --output=$@ $<

nm-settings-bindings.h: $(top_srcdir)/introspection/nm-settings.xml
	dbus-binding-tool --prefix=nm_settings --mode=glib-client --output=$@ $<

nm-settings-system-bindings.h: $(top_srcdir)/introspection/nm-settings-system.xml
	dbus-binding-tool --prefix=nm_settings_system --mode=glib-client --output=$@ $<

nm-exported-connection-glue.h: $(top_srcdir)/introspection/nm-exported-connection.xml
	dbus-binding-tool --prefix=nm_exported_connection --mode=glib-server --output=$@ $<

nm-exported-connection-bindings.h: $(top_srcdir)/introspection/nm-exported-connection.xml
	dbus-binding-tool --prefix=nm_exported_connection --mode=glib-client --output=$@ $<

nm-vpn-connection-bindings.h: $(top_srcdir)/introspection/nm-vpn-connection.xml
	dbus-binding-tool --prefix=nm_vpn_connection --mode=glib-client --output=$@ $<

nm-vpn-plugin-glue.h: $(top_srcdir)/introspection/nm-vpn-plugin.xml
	dbus-binding-tool --prefix=nm_vpn_plugin --mode=glib-server --output=$@ $<

nm-active-connection-bindings.h: $(top_srcdir)/introspection/nm-active-connection.xml
	dbus-binding-tool --prefix=nm_active_connection --mode=glib-client --output=$@ $<

nm-ip4-config-bindings.h: $(top_srcdir)/introspection/nm-ip4-config.xml
	dbus-binding-tool --prefix=nm_ip4_config --mode=glib-client --output=$@ $<

nm-dhcp4-config-bindings.h: $(top_srcdir)/introspection/nm-dhcp4-config.xml
	dbus-binding-tool --prefix=nm_dhcp4_config --mode=glib-client --output=$@ $<

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm_glib.pc libnm_glib_vpn.pc

DISTCLEANFILES = libnm_glib.pc libnm_glib.pc

EXTRA_DIST = libnm_glib.pc.in libnm_glib_vpn.pc.in libnm_glib.ver libnm_glib_vpn.ver

CLEANFILES = \
	$(BUILT_SOURCES)
