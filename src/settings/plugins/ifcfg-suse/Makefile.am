AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-ifcfg-suse"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DSYSCONFDIR=\"$(sysconfdir)\"

pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-suse.la

libnm_settings_plugin_ifcfg_suse_la_SOURCES = \
	plugin.c \
	plugin.h

libnm_settings_plugin_ifcfg_suse_la_LDFLAGS = -module -avoid-version
