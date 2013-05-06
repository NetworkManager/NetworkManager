if WITH_PPP

INCLUDES = \
	-I${top_builddir}/include \
	-I${top_srcdir}/include

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-pppd-plugin.la

nm_pppd_plugin_la_SOURCES = \
	nm-pppd-plugin.c \
	nm-pppd-plugin.h \
	nm-ppp-status.h

nm_pppd_plugin_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

nm_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_pppd_plugin_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

endif
