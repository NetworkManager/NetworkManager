
INCLUDES = \
	-I$(top_srcdir)/src/system-settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util

pkglib_LTLIBRARIES = libnm-settings-plugin-ifupdown.la

libnm_settings_plugin_ifupdown_la_SOURCES = \
	interface_parser.c \
	interface_parser.h \
	nm-ifupdown-connection.c \
	nm-ifupdown-connection.h \
	parser.c \
	parser.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifupdown_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifupdown_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifupdown_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(GUDEV_LIBS)

