SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-ifupdown"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

noinst_LTLIBRARIES = libifupdown-io.la

libifupdown_io_la_SOURCES = \
	interface_parser.c \
	interface_parser.h \
	parser.c \
	parser.h

pkglib_LTLIBRARIES = libnm-settings-plugin-ifupdown.la

libnm_settings_plugin_ifupdown_la_SOURCES = \
	nm-ifupdown-connection.c \
	nm-ifupdown-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifupdown_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifupdown_la_LIBADD = libifupdown-io.la

