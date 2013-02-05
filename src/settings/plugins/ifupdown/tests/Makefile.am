if ENABLE_TESTS

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/../

noinst_PROGRAMS = test-ifupdown

test_ifupdown_SOURCES = \
	test-ifupdown.c \
	../interface_parser.c \
	../parser.c

test_ifupdown_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_ENI_DIR=\"$(abs_srcdir)\"

test_ifupdown_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS)

check-local: test-ifupdown
	$(abs_builddir)/test-ifupdown

EXTRA_DIST = \
	test1 test2 test3 test4 test5 test6 test7 test8 test9 test11 test12 \
	test13 test14 test15 test16 test17-wired-static-verify-ip4 \
	test18-wired-static-verify-ip6 test19-wired-static-verify-ip4-plen

endif
