AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-example"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DNMCONFDIR=\"$(nmconfdir)\"

# 'noinst' here because this is an example plugin we don't want to install
noinst_LTLIBRARIES = libnm-settings-plugin-example.la

# The actual plugins typically pull reader.c and writer.c out into
# their own static library so that unit tests can use them without
# having to build the entire plugin.  But since this is a simple
# plugin we don't do that yet.

libnm_settings_plugin_example_la_SOURCES = \
	nm-example-connection.c \
	nm-example-connection.h \
	plugin.c \
	plugin.h \
	common.h \
	reader.c \
	writer.c

libnm_settings_plugin_example_la_LDFLAGS = -module -avoid-version

