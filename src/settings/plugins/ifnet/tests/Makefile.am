if ENABLE_TESTS

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS= \
	-I$(srcdir)/../ \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager-ifnet"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(CHECK_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-DTEST_IFNET_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\" \
	-DTEST_WPA_SUPPLICANT_CONF='"$(srcdir)/wpa_supplicant.conf"' \
	-DSYSCONFDIR=\"nonexistent\"

noinst_PROGRAMS = check_ifnet
check_ifnet_SOURCES = \
	test_all.c \
	../connection_parser.c \
	../net_parser.c \
	../net_utils.c \
	../wpa_parser.c

check_ifnet_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS)

check_ifnet_LDADD = $(top_builddir)/src/libNetworkManager.la

#@VALGRIND_RULES@
TESTS = check_ifnet

endif

EXTRA_DIST = \
	hostname \
	net \
	net.all \
	nm-system-settings.conf \
	wpa_supplicant.conf \
	test_ca_cert.pem
