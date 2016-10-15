AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/devices \
	-I${top_srcdir}/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DSRCDIR=\""$(abs_srcdir)"\" \
	-DBUILDDIR=\""$(abs_builddir)"\"

noinst_PROGRAMS = \
	test-config

test_config_SOURCES = \
	nm-test-device.c \
	nm-test-device.h \
	test-config.c

test_config_LDADD = \
	$(top_builddir)/src/libNetworkManagerTest.la

@NM_LOG_COMPILER@
TESTS = test-config

EXTRA_DIST = \
	NetworkManager.conf \
	NetworkManager.state \
	bad.conf \
	global-dns-invalid.conf \
	conf.d/00-overrides.conf \
	conf.d/10-more.conf \
	conf.d/20-config-enable-1.conf \
	conf.d/90-last.conf
