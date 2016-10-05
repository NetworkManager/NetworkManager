SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DNMCONFDIR=\"$(nmconfdir)\"

noinst_LTLIBRARIES = \
	libkeyfile-io.la \
	libnm-settings-plugin-keyfile.la

##### I/O library for testcases #####

libkeyfile_io_la_SOURCES = \
	nms-keyfile-reader.c \
	nms-keyfile-reader.h \
	nms-keyfile-writer.c \
	nms-keyfile-writer.h \
	nms-keyfile-utils.c \
	nms-keyfile-utils.h

libkeyfile_io_la_LIBADD = $(GLIB_LIBS)

#####################################

libnm_settings_plugin_keyfile_la_SOURCES = \
	nms-keyfile-connection.c \
	nms-keyfile-connection.h \
	nms-keyfile-plugin.c \
	nms-keyfile-plugin.h

libnm_settings_plugin_keyfile_la_LIBADD = \
	libkeyfile-io.la

keyfiledir=$(sysconfdir)/NetworkManager/system-connections

install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(keyfiledir)

