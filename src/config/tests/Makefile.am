INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/src/config

noinst_PROGRAMS = \
	test-config

test_config_SOURCES = \
	nm-test-device.c \
	nm-test-device.h \
	test-config.c

test_config_CPPFLAGS = \
	-DSRCDIR=\""$(srcdir)"\" \
	$(GLIB_CFLAGS)

test_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

check-local: test-config
	$(abs_builddir)/test-config

EXTRA_DIST = \
	NetworkManager.conf \
	bad.conf \
	conf.d/00-overrides.conf \
	conf.d/10-more.conf \
	conf.d/90-last.conf
