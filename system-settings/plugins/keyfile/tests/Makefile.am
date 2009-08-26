SUBDIRS=keyfiles

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/system-settings/plugins/keyfile/io

noinst_PROGRAMS = test-keyfile

test_keyfile_SOURCES = \
	test-keyfile.c

test_keyfile_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_KEYFILES_DIR=\"$(abs_srcdir)/keyfiles\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/keyfiles\"

test_keyfile_LDADD = \
	$(top_builddir)/system-settings/plugins/keyfile/io/libkeyfile-io.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS)

if WITH_TESTS

check-local: test-keyfile
	$(abs_builddir)/test-keyfile

endif

