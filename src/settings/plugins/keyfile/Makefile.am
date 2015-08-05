SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-keyfile"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DNMCONFDIR=\"$(nmconfdir)\"

noinst_LTLIBRARIES = \
	libkeyfile-io.la \
	libnm-settings-plugin-keyfile.la

##### I/O library for testcases #####

libkeyfile_io_la_SOURCES = \
	reader.c \
	reader.h \
	writer.c \
	writer.h \
	utils.c \
	utils.h \
	common.h

libkeyfile_io_la_LIBADD = $(GLIB_LIBS)

#####################################

libnm_settings_plugin_keyfile_la_SOURCES = \
	nm-keyfile-connection.c \
	nm-keyfile-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_keyfile_la_LIBADD = \
	libkeyfile-io.la

keyfiledir=$(sysconfdir)/NetworkManager/system-connections

install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(keyfiledir)

