INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_builddir}/src/marshallers

noinst_LTLIBRARIES = libppp-manager.la

libppp_manager_la_SOURCES = \
	nm-ppp-manager.c \
	nm-ppp-manager.h \
	nm-ppp-status.h

libppp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(HAL_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBDIR=\"$(libdir)\" \
	-DPLUGINDIR=\"$(pkglibdir)\"

libppp_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/src/marshallers/libmarshallers.la

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
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la

nm-pppd-plugin-glue.h: nm-pppd-plugin.xml
	dbus-binding-tool --prefix=nm_pppd_plugin --mode=glib-server --output=nm-pppd-plugin-glue.h $(top_srcdir)/src/ppp-manager/nm-pppd-plugin.xml

BUILT_SOURCES = nm-pppd-plugin-glue.h

EXTRA_DIST = nm-pppd-plugin.xml

CLEANFILES = $(BUILT_SOURCES)

