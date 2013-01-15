if ENABLE_TESTS

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I$(top_srcdir)/src/dhcp-manager

noinst_PROGRAMS = test-dhcp-dhclient

####### policy /etc/hosts test #######

test_dhcp_dhclient_SOURCES = \
	test-dhcp-dhclient.c

test_dhcp_dhclient_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DTESTDIR="\"$(abs_srcdir)\""

test_dhcp_dhclient_LDADD = \
	-ldl \
	$(top_builddir)/src/dhcp-manager/libdhcp-dhclient.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)

check-local: test-dhcp-dhclient
	$(abs_builddir)/test-dhcp-dhclient

endif

EXTRA_DIST = \
	test-dhclient-duid.leases \
	test-dhclient-commented-duid.leases

