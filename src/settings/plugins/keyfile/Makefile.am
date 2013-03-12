SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

INCLUDES = \
	-I$(top_srcdir)/src/config \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util

noinst_LTLIBRARIES = \
	libkeyfile-io.la \
	libnm-settings-plugin-keyfile.la

##### I/O library for testcases #####

libkeyfile_io_la_SOURCES = \
	reader.c \
	reader.h \
	writer.c \
	writer.h \
	errors.c \
	utils.c \
	utils.h \
	common.h

libkeyfile_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DNMCONFDIR=\"$(nmconfdir)\"

libkeyfile_io_la_LIBADD = $(GLIB_LIBS)

#####################################

libnm_settings_plugin_keyfile_la_SOURCES = \
	nm-keyfile-connection.c \
	nm-keyfile-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_keyfile_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DNMCONFDIR=\"$(nmconfdir)\"

libnm_settings_plugin_keyfile_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	libkeyfile-io.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

libnm_settings_plugin_keyfile_la_LDFLAGS = -rdynamic

keyfiledir=$(sysconfdir)/NetworkManager/system-connections

install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(keyfiledir)

