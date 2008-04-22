
pkglib_LTLIBRARIES = libnm-settings-plugin-keyfile.la

libnm_settings_plugin_keyfile_la_SOURCES = \
	plugin.c \
	plugin.h \
	reader.c \
	reader.h \
	writer.c \
	writer.h

libnm_settings_plugin_keyfile_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-I${top_srcdir}/system-settings/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-DKEYFILE_DIR=\""$(sysconfdir)/NetworkManager/system_config"\"

libnm_settings_plugin_keyfile_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_keyfile_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(GIO_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la

