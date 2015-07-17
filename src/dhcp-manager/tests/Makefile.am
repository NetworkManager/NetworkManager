AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTESTDIR="\"$(abs_srcdir)\""

noinst_PROGRAMS = \
	test-dhcp-dhclient \
	test-dhcp-utils

####### dhclient leases test #######

test_dhcp_dhclient_SOURCES = \
	$(top_srcdir)/src/dhcp-manager/nm-dhcp-dhclient-utils.h \
	$(top_srcdir)/src/dhcp-manager/nm-dhcp-dhclient-utils.c \
	$(top_srcdir)/src/dhcp-manager/nm-dhcp-utils.h \
	$(top_srcdir)/src/dhcp-manager/nm-dhcp-utils.c \
	test-dhcp-dhclient.c

test_dhcp_dhclient_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### DHCP utils test #######

test_dhcp_utils_SOURCES = \
	test-dhcp-utils.c

test_dhcp_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

#################################

@VALGRIND_RULES@
TESTS = test-dhcp-dhclient test-dhcp-utils

EXTRA_DIST = \
	test-dhclient-duid.leases \
	test-dhclient-commented-duid.leases \
	leases/basic.leases \
	leases/malformed1.leases \
	leases/malformed2.leases \
	leases/malformed3.leases

