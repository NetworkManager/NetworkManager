AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/src/config \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	-DSRCDIR=\""$(srcdir)"\"

noinst_PROGRAMS = \
	test-config

test_config_SOURCES = \
	nm-test-device.c \
	nm-test-device.h \
	test-config.c

test_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

TESTS = test-config

EXTRA_DIST = \
	NetworkManager.conf \
	bad.conf \
	conf.d/00-overrides.conf \
	conf.d/10-more.conf \
	conf.d/90-last.conf
