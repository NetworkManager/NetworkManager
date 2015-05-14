AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I${top_srcdir}/src/platform \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/devices/wifi \
	-I$(top_builddir)/src \
	-DG_LOG_DOMAIN=\""NetworkManager-wifi"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = test-wifi-ap-utils

test_wifi_ap_utils_SOURCES = \
	test-wifi-ap-utils.c \
	$(srcdir)/../nm-wifi-ap.c \
	$(srcdir)/../nm-wifi-ap.h \
	$(srcdir)/../nm-wifi-ap-utils.c \
	$(srcdir)/../nm-wifi-ap-utils.h

test_wifi_ap_utils_LDADD = $(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
AM_TESTS_FD_REDIRECT = --tap
LOG_DRIVER = $(top_srcdir)/build-aux/tap-driver.sh
TESTS = test-wifi-ap-utils

