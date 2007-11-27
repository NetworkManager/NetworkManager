
lib_LTLIBRARIES = libnm-settings-plugin-ifcfg.la

libnm_settings_plugin_ifcfg_la_SOURCES = \
	shvar.c \
	shvar.h \
	parser.c \
	parser.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifcfg_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-I${top_srcdir}/system-settings/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifcfg_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la

