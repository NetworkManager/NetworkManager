INCLUDES = \
	-I${top_srcdir} \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_builddir}/src/generated \
	-I${top_srcdir}/src/generated \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/posix-signals

noinst_LTLIBRARIES = libppp-manager.la

libppp_manager_la_SOURCES = \
	nm-ppp-manager.c \
	nm-ppp-manager.h \
	nm-ppp-status.h

nm-ppp-manager-glue.h: $(top_srcdir)/introspection/nm-ppp-manager.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_ppp_manager --mode=glib-server --output=$@ $<

built_sources = nm-ppp-manager-glue.h

$(libppp_manager_la_OBJECTS): $(built_sources)

libppp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBDIR=\"$(libdir)\" \
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\"

libppp_manager_la_LIBADD = \
	$(top_builddir)/src/generated/libnm-generated.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/src/posix-signals/libnm-posix-signals.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

if WITH_PPP

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

BUILT_SOURCES = nm-ppp-manager-glue.h

CLEANFILES = $(BUILT_SOURCES)

