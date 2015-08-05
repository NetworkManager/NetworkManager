SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

pkglib_LTLIBRARIES = libnm-settings-plugin-ibft.la

noinst_LTLIBRARIES = libibft-io.la

libibft_io_la_SOURCES = \
	reader.c \
	reader.h

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager-ibft"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

libnm_settings_plugin_ibft_la_SOURCES = \
	plugin.c \
	plugin.h \
	nm-ibft-connection.c \
	nm-ibft-connection.h

libnm_settings_plugin_ibft_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ibft_la_LIBADD = libibft-io.la

CLEANFILES = $(BUILT_SOURCES)

