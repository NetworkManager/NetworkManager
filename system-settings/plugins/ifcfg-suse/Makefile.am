
pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-suse.la

libnm_settings_plugin_ifcfg_suse_la_SOURCES = \
	nm-suse-connection.c \
	nm-suse-connection.h \
	shvar.c \
	shvar.h \
	parser.c \
	parser.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifcfg_suse_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-I${top_srcdir}/system-settings/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifcfg_suse_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifcfg_suse_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(GIO_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm_glib.la

