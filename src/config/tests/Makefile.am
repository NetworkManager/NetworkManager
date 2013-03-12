if ENABLE_TESTS

INCLUDES = \
	-I$(top_srcdir)/src/config

noinst_PROGRAMS = \
	test-config

test_config_CPPFLAGS = \
	-DSRCDIR=\""$(srcdir)"\" \
	$(GLIB_CFLAGS)

test_config_LDADD = \
	$(top_builddir)/src/config/libnm-config.la \
	$(top_builddir)/src/logging/libnm-logging.la

check-local: test-config
	$(abs_builddir)/test-config

EXTRA_DIST = \
	NetworkManager.conf \
	bad.conf

endif
