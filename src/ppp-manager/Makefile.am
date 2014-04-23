if WITH_PPP

AM_CPPFLAGS = \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-DG_LOG_DOMAIN=\""nm-pppd-plugin"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-pppd-plugin.la

nm_pppd_plugin_la_SOURCES = \
	nm-pppd-plugin.c \
	nm-pppd-plugin.h \
	nm-ppp-status.h

nm_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_pppd_plugin_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

endif
