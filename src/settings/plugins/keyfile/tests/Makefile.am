if ENABLE_TESTS

SUBDIRS=keyfiles

noinst_PROGRAMS = test-keyfile

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(srcdir)/../ \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_KEYFILES_DIR=\"$(abs_srcdir)/keyfiles\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/keyfiles\"

test_keyfile_SOURCES = \
	test-keyfile.c

test_keyfile_LDADD = \
	$(builddir)/../libkeyfile-io.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS)

check-local: test-keyfile
	$(abs_builddir)/test-keyfile

endif
