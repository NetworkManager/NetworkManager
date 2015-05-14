if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_NM_SERVICE=\"$(abs_top_srcdir)/tools/test-networkmanager-service.py\" \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = $(TESTS)

if WITH_VALGRIND
@VALGRIND_RULES@ --launch-dbus
else
LOG_COMPILER = $(srcdir)/libnm-glib-test-launch.sh
endif
TESTS = test-nm-client test-remote-settings-client

####### NMClient and non-settings tests #######

test_nm_client_SOURCES = \
	common.c \
	common.h \
	test-nm-client.c

test_nm_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

####### remote settings client test #######

test_remote_settings_client_SOURCES = \
	common.c \
	common.h \
	test-remote-settings-client.c

test_remote_settings_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

endif

EXTRA_DIST = libnm-glib-test-launch.sh
