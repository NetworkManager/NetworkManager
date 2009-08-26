SUBDIRS=io tests

INCLUDES = \
	-I$(top_srcdir)/src/system-settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/system-settings/plugins/keyfile/io

pkglib_LTLIBRARIES = libnm-settings-plugin-keyfile.la

libnm_settings_plugin_keyfile_la_SOURCES = \
	nm-keyfile-connection.c \
	nm-keyfile-connection.h \
	plugin.c \
	plugin.h

keyfiledir=$(sysconfdir)/NetworkManager/system-connections

libnm_settings_plugin_keyfile_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DG_DISABLE_DEPRECATED \
	-DKEYFILE_DIR=\""$(keyfiledir)"\"

libnm_settings_plugin_keyfile_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_keyfile_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/system-settings/plugins/keyfile/io/libkeyfile-io.la \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(DBUS_LIBS) \
	$(GIO_LIBS)

install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(keyfiledir)

