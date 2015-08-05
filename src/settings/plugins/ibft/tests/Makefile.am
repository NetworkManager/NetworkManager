if ENABLE_TESTS

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/../ \
	-DG_LOG_DOMAIN=\""NetworkManager-ibft"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_IBFT_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\"

AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

noinst_PROGRAMS = test-ibft

test_ibft_SOURCES = \
	test-ibft.c \
	../reader.c

test_ibft_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-ibft

endif

EXTRA_DIST = \
	iscsiadm-test-dhcp \
	iscsiadm-test-static \
	iscsiadm-test-bad-ipaddr \
	iscsiadm-test-bad-gateway \
	iscsiadm-test-bad-dns1 \
	iscsiadm-test-bad-dns2 \
	iscsiadm-test-bad-entry \
	iscsiadm-test-bad-record \
	iscsiadm-test-vlan

