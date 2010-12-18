INCLUDES = \
	-I$(top_srcdir)/include \
	-I${top_srcdir}/libnm-util \
	-I$(top_srcdir)/src/dhcp-manager

noinst_PROGRAMS = test-dhcp-dhclient

####### policy /etc/hosts test #######

test_dhcp_dhclient_SOURCES = \
	test-dhcp-dhclient.c

test_dhcp_dhclient_CPPFLAGS = \
	$(GLIB_CFLAGS)

test_dhcp_dhclient_LDADD = \
	-ldl \
	$(top_builddir)/src/dhcp-manager/libdhcp-dhclient.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)

if WITH_TESTS

check-local: test-dhcp-dhclient
	$(abs_builddir)/test-dhcp-dhclient

endif

