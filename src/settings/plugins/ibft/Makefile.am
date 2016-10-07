SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

pkglib_LTLIBRARIES = libnm-settings-plugin-ibft.la

noinst_LTLIBRARIES = libibft-io.la

libibft_io_la_SOURCES = \
	nms-ibft-reader.c \
	nms-ibft-reader.h

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

libnm_settings_plugin_ibft_la_SOURCES = \
	nms-ibft-plugin.c \
	nms-ibft-plugin.h \
	nms-ibft-connection.c \
	nms-ibft-connection.h

libnm_settings_plugin_ibft_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ibft_la_LIBADD = libibft-io.la

CLEANFILES = $(BUILT_SOURCES)

