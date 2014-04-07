SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/logging \
	-I$(top_srcdir)/src/config \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-DG_LOG_DOMAIN=\""NetworkManager-ifupdown"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

noinst_LTLIBRARIES = libifupdown-io.la

libifupdown_io_la_SOURCES = \
	interface_parser.c \
	interface_parser.h \
	parser.c \
	parser.h

libifupdown_io_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)

pkglib_LTLIBRARIES = libnm-settings-plugin-ifupdown.la

libnm_settings_plugin_ifupdown_la_SOURCES = \
	nm-ifupdown-connection.c \
	nm-ifupdown-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifupdown_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifupdown_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	libifupdown-io.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS)

