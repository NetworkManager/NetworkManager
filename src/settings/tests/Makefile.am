INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/src/settings

noinst_PROGRAMS = \
	test-wired-defname

####### wired defname test #######

test_wired_defname_SOURCES = \
	test-wired-defname.c

test_wired_defname_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_wired_defname_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/settings/libtest-settings-utils.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

if WITH_TESTS

check-local: test-wired-defname
	$(abs_builddir)/test-wired-defname

endif

