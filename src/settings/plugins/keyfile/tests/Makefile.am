if ENABLE_TESTS

SUBDIRS=keyfiles

@GNOME_CODE_COVERAGE_RULES@

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/../

noinst_PROGRAMS = test-keyfile

test_keyfile_SOURCES = \
	test-keyfile.c \
	../reader.c \
	../writer.c \
	../errors.c \
	../utils.c

test_keyfile_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-DTEST_KEYFILES_DIR=\"$(abs_srcdir)/keyfiles\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/keyfiles\" \
	-DNMCONFDIR=\"nonexistent\"

test_keyfile_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

check-local: test-keyfile
	$(abs_builddir)/test-keyfile

endif
