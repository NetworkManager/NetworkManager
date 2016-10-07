SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"
	-DSBINDIR=\"$(sbindir)\"

pkglib_LTLIBRARIES = \
	libnm-settings-plugin-ifnet.la

noinst_LTLIBRARIES = \
	libnms-ifnet-core.la

###############################################################################

libnms_ifnet_core_la_SOURCES = \
	net_parser.c\
	net_parser.h\
	connection_parser.c \
	connection_parser.h \
	net_utils.h\
	net_utils.c\
	wpa_parser.h\
	wpa_parser.c

###############################################################################

libnm_settings_plugin_ifnet_la_SOURCES = \
	nm-ifnet-connection.c \
	nm-ifnet-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifnet_la_LDFLAGS = \
	-module -avoid-version

libnm_settings_plugin_ifnet_la_LIBADD = \
	libnms-ifnet-core.la
