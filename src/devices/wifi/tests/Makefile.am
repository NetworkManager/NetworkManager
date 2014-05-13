AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/logging \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/devices/wifi \
	-I$(top_builddir)/src \
	-DG_LOG_DOMAIN=\""NetworkManager-wifi"\" \
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

TESTS = test-wifi-ap-utils

