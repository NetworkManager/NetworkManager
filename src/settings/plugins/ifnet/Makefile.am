SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

include $(top_srcdir)/nm.mk

pkglib_LTLIBRARIES = \
	libnm-settings-plugin-ifnet.la

noinst_LTLIBRARIES = \
	libnms-ifnet-core.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"
	-DSBINDIR=\"$(sbindir)\"

###############################################################################

libnms_ifnet_core_la_SOURCES = \
	nms-ifnet-net-parser.c\
	nms-ifnet-net-parser.h\
	nms-ifnet-connection-parser.c \
	nms-ifnet-connection-parser.h \
	nms-ifnet-net-utils.h\
	nms-ifnet-net-utils.c\
	nms-ifnet-wpa-parser.h\
	nms-ifnet-wpa-parser.c

###############################################################################

libnm_settings_plugin_ifnet_la_SOURCES = \
	nms-ifnet-connection.c \
	nms-ifnet-connection.h \
	nms-ifnet-plugin.c \
	nms-ifnet-plugin.h

libnm_settings_plugin_ifnet_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(top_srcdir)/linker-script-settings.ver"

libnm_settings_plugin_ifnet_la_LIBADD = \
	libnms-ifnet-core.la

###############################################################################

check-local:
	$(call check_so_symbols,$(builddir)/.libs/libnm-settings-plugin-ifnet.so)
