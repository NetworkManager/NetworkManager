AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(POLKIT_CFLAGS) \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-DG_LOG_DOMAIN=\""NetworkManager-ifcfg-suse"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DSYSCONFDIR=\"$(sysconfdir)\"

pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-suse.la

libnm_settings_plugin_ifcfg_suse_la_SOURCES = \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifcfg_suse_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifcfg_suse_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(GLIB_LIBS)

