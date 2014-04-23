AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/src/settings \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = \
	test-wired-defname

####### wired defname test #######

test_wired_defname_SOURCES = \
	test-wired-defname.c

test_wired_defname_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

###########################################

TESTS = test-wired-defname
