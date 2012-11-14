SUBDIRS = . tests

INCLUDES = \
	-I$(top_srcdir)/src/wifi \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util

pkglib_LTLIBRARIES = libnm-settings-plugin-ifnet.la

noinst_LTLIBRARIES = lib-ifnet-io.la

libnm_settings_plugin_ifnet_la_SOURCES = \
	nm-ifnet-connection.c \
	nm-ifnet-connection.h \
	plugin.c \
	plugin.h 

libnm_settings_plugin_ifnet_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifnet_la_LDFLAGS = -module -avoid-version

libnm_settings_plugin_ifnet_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	lib-ifnet-io.la\
	$(GLIB_LIBS) \
	$(GUDEV_LIBS)

lib_ifnet_io_la_SOURCES = \
	net_parser.c\
	net_parser.h\
	connection_parser.c \
	connection_parser.h \
	net_utils.h\
	net_utils.c\
	wpa_parser.h\
	wpa_parser.c

lib_ifnet_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

lib_ifnet_io_la_LIBADD = \
	 $(top_builddir)/src/wifi/libwifi-utils.la \
	 $(top_builddir)/libnm-util/libnm-util.la \
	 $(GLIB_LIBS)
