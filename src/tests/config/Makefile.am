AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/devices \
	-I${top_srcdir}/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DSRCDIR=\""$(srcdir)"\" \
	-DBUILDDIR=\""$(builddir)"\"

noinst_PROGRAMS = \
	test-config

test_config_SOURCES = \
	nm-test-device.c \
	nm-test-device.h \
	test-config.c

test_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-config

EXTRA_DIST = \
	NetworkManager.conf \
	bad.conf \
	conf.d/00-overrides.conf \
	conf.d/10-more.conf \
	conf.d/90-last.conf
