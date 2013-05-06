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
	$(top_builddir)/src/libNetworkManager.la

check-local: test-dhcp-dhclient
	$(abs_builddir)/test-dhcp-dhclient

EXTRA_DIST = \
	test-dhclient-duid.leases \
	test-dhclient-commented-duid.leases

