INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(srcdir)/../

noinst_PROGRAMS = test-ifupdown

test_ifupdown_SOURCES = \
	test-ifupdown.c

test_ifupdown_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_ENI_DIR=\"$(abs_srcdir)\"

test_ifupdown_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(builddir)/../libifupdown-io.la \
	$(DBUS_LIBS)

if WITH_TESTS

check-local: test-ifupdown
	$(abs_builddir)/test-ifupdown

endif

EXTRA_DIST = \
	test1 test2 test3 test4 test5 test6 test7 test8 test9 test11 test12 \
	test13 test14 test15 test16
