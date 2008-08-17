
pkglib_LTLIBRARIES = libnm-settings-plugin-keyfile.la

libnm_settings_plugin_keyfile_la_SOURCES = \
	nm-keyfile-connection.c \
	nm-keyfile-connection.h \
	plugin.c \
	plugin.h \
	reader.c \
	reader.h \
	writer.c \
	writer.h

keyfiledir=$(sysconfdir)/NetworkManager/system-connections

libnm_settings_plugin_keyfile_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-I${top_srcdir}/system-settings/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I${top_srcdir}/libnm-glib \
	-DKEYFILE_DIR=\""$(keyfiledir)"\"

libnm_settings_plugin_keyfile_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_keyfile_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(DBUS_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm_glib.la

if NO_GIO
libnm_settings_plugin_keyfile_la_LIBADD += \
	$(top_builddir)/gfilemonitor/libgfilemonitor.la
else
libnm_settings_plugin_keyfile_la_LIBADD += \
	$(GIO_LIBS)
endif

install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(keyfiledir)

