INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_builddir)/marshallers \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src

noinst_PROGRAMS = \
	test-dhcp-options \
	test-policy-hosts \
	test-wifi-ap-utils

####### DHCP options test #######

test_dhcp_options_SOURCES = \
	test-dhcp-options.c

test_dhcp_options_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\"

test_dhcp_options_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/dhcp-manager/libdhcp-manager.la \
	$(top_builddir)/src/libtest-dhcp.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

####### policy /etc/hosts test #######

test_policy_hosts_SOURCES = \
	test-policy-hosts.c

test_policy_hosts_CPPFLAGS = \
	$(GLIB_CFLAGS)

test_policy_hosts_LDADD = \
	-ldl \
	$(top_builddir)/src/libtest-policy-hosts.la \
	$(GLIB_LIBS)

####### wifi ap utils test #######

test_wifi_ap_utils_SOURCES = \
	test-wifi-ap-utils.c

test_wifi_ap_utils_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_wifi_ap_utils_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/libtest-wifi-ap-utils.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

####### secret agent interface test #######

EXTRA_DIST = test-secret-agent.py

###########################################

if WITH_TESTS

check-local: test-dhcp-options test-policy-hosts test-wifi-ap-utils
	$(abs_builddir)/test-dhcp-options
	$(abs_builddir)/test-policy-hosts
	$(abs_builddir)/test-wifi-ap-utils

endif

