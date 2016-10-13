if ENABLE_TESTS

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS= \
	-I$(srcdir)/../ \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(CHECK_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-DTEST_IFNET_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\" \
	-DTEST_WPA_SUPPLICANT_CONF='"$(srcdir)/wpa_supplicant.conf"' \
	-DSYSCONFDIR=\"nonexistent\"

noinst_PROGRAMS = test-ifnet

test_ifnet_SOURCES = \
	test-ifnet.c

test_ifnet_LDFLAGS = \
	$(GLIB_LDFLAGS)
	$(CODE_COVERAGE_LDFLAGS)

test_ifnet_LDADD = \
	$(top_builddir)/src/settings/plugins/ifnet/libnms-ifnet-core.la \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-ifnet

endif

EXTRA_DIST = \
	net \
	net.all \
	nm-system-settings.conf \
	wpa_supplicant.conf \
	test_ca_cert.pem
