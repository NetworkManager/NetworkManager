include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/src/devices \
	-I${top_srcdir}/src/platform \
	-I${top_builddir}/introspection \
	-I${top_srcdir}/include \
	-I$(top_builddir)/include \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager-team"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS)

if WITH_TEAMDCTL
AM_CPPFLAGS += ${LIBTEAMDCTL_CFLAGS}
endif

pkglib_LTLIBRARIES = libnm-device-plugin-team.la

SYMBOL_VIS_FILE=$(srcdir)/exports.ver

libnm_device_plugin_team_la_SOURCES = \
	nm-device-team.c \
	nm-device-team.h \
	nm-team-factory.c \
	nm-team-factory.h

libnm_device_plugin_team_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script=$(SYMBOL_VIS_FILE)

libnm_device_plugin_team_la_LIBADD = \
	$(top_builddir)/introspection/libnmdbus.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS)

if WITH_TEAMDCTL
libnm_device_plugin_team_la_LIBADD += $(LIBTEAMDCTL_LIBS)
endif

EXTRA_DIST = $(SYMBOL_VIS_FILE)

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-device-plugin-team.so $(SYMBOL_VIS_FILE)

endif

