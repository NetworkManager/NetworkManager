SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

pkglib_LTLIBRARIES = \
	libnm-settings-plugin-ifcfg-rh.la

noinst_LTLIBRARIES = \
	libnmdbus-ifcfg-rh.la \
	libnms-ifcfg-rh-core.la

BUILT_SOURCES = \
	nmdbus-ifcfg-rh.h \
	nmdbus-ifcfg-rh.c

###############################################################################

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	$(NSS_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

###############################################################################

nodist_libnmdbus_ifcfg_rh_la_SOURCES = \
	nmdbus-ifcfg-rh.c \
	nmdbus-ifcfg-rh.h

libnmdbus_ifcfg_rh_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nmdbus-ifcfg-rh.h: nm-ifcfg-rh.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix com.redhat \
		$<

nmdbus-ifcfg-rh.c: nmdbus-ifcfg-rh.h
	@true

###############################################################################

libnms_ifcfg_rh_core_la_SOURCES = \
	nms-ifcfg-rh-common.h \
	shvar.c \
	shvar.h \
	nms-ifcfg-rh-utils.c \
	nms-ifcfg-rh-utils.h \
	nms-ifcfg-rh-reader.c \
	nms-ifcfg-rh-reader.h \
	nms-ifcfg-rh-writer.c \
	nms-ifcfg-rh-writer.h

###############################################################################

libnm_settings_plugin_ifcfg_rh_la_SOURCES =
	nms-ifcfg-rh-connection.c \
	nms-ifcfg-rh-connection.h \
	nms-ifcfg-rh-plugin.c \
	nms-ifcfg-rh-plugin.h

libnm_settings_plugin_ifcfg_rh_la_LDFLAGS = \
	-module -avoid-version

libnm_settings_plugin_ifcfg_rh_la_LIBADD = \
	libnms-ifcfg-rh-core.la \
	libnmdbus-ifcfg-rh.la

###############################################################################

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-ifcfg-rh.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	nm-ifcfg-rh.xml

CLEANFILES = $(BUILT_SOURCES)

