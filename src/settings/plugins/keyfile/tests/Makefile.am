if ENABLE_TESTS

SUBDIRS=keyfiles

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/../ \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager-keyfile"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_KEYFILES_DIR=\"$(abs_srcdir)/keyfiles\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/keyfiles\" \
	-DNMCONFDIR=\"nonexistent\"

noinst_PROGRAMS = test-keyfile

test_keyfile_SOURCES = \
	test-keyfile.c \
	../reader.c \
	../writer.c \
	../utils.c

test_keyfile_LDADD = \
	$(top_builddir)/src/libNetworkManager.la \
	$(DBUS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

@VALGRIND_RULES@
TESTS = test-keyfile

endif
