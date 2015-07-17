SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

nm-ifcfg-rh-glue.h: nm-ifcfg-rh.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_ifcfg_rh --mode=glib-server --output=$@ $<

BUILT_SOURCES = \
	nm-ifcfg-rh-glue.h

pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-rh.la

noinst_LTLIBRARIES = libifcfg-rh-io.la

libifcfg_rh_io_la_SOURCES = \
	shvar.c \
	shvar.h \
	reader.c \
	reader.h \
	writer.c \
	writer.h \
	common.h \
	utils.c \
	utils.h

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(NSS_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager-ifcfg-rh"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

libnm_settings_plugin_ifcfg_rh_la_SOURCES = \
	plugin.c \
	plugin.h \
	nm-ifcfg-connection.c \
	nm-ifcfg-connection.h

libnm_settings_plugin_ifcfg_rh_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifcfg_rh_la_LIBADD = libifcfg-rh-io.la

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-ifcfg-rh.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	nm-ifcfg-rh.xml

CLEANFILES = $(BUILT_SOURCES)

