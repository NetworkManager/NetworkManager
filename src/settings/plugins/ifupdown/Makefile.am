SUBDIRS = . tests

INCLUDES = \
	-I$(top_srcdir)/src/logging \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util

noinst_LTLIBRARIES = libifupdown-io.la

libifupdown_io_la_SOURCES = \
	interface_parser.c \
	interface_parser.h \
	parser.c \
	parser.h

libifupdown_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libifupdown_io_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)

pkglib_LTLIBRARIES = libnm-settings-plugin-ifupdown.la

libnm_settings_plugin_ifupdown_la_SOURCES = \
	nm-ifupdown-connection.c \
	nm-ifupdown-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifupdown_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifupdown_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifupdown_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	libifupdown-io.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS)

