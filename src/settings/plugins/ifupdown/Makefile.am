SUBDIRS = . tests

@GNOME_CODE_COVERAGE_RULES@

include $(top_srcdir)/nm.mk

pkglib_LTLIBRARIES = \
	libnm-settings-plugin-ifupdown.la

noinst_LTLIBRARIES = \
	libnms-ifupdown-core.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

###############################################################################

libnms_ifupdown_core_la_SOURCES = \
	nms-ifupdown-interface-parser.c \
	nms-ifupdown-interface-parser.h \
	nms-ifupdown-parser.c \
	nms-ifupdown-parser.h

###############################################################################

libnm_settings_plugin_ifupdown_la_SOURCES = \
	nms-ifupdown-connection.c \
	nms-ifupdown-connection.h \
	nms-ifupdown-plugin.c \
	nms-ifupdown-plugin.h

libnm_settings_plugin_ifupdown_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(top_srcdir)/linker-script-settings.ver"

libnm_settings_plugin_ifupdown_la_LIBADD = \
	libnms-ifupdown-core.la

###############################################################################

check-local:
	$(call check_so_symbols,$(builddir)/.libs/libnm-settings-plugin-ifupdown.so)
