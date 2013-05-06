INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/src/dhcp-manager \
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
	$(top_builddir)/src/libNetworkManager.la

####### policy /etc/hosts test #######

test_policy_hosts_SOURCES = \
	test-policy-hosts.c

test_policy_hosts_CPPFLAGS = \
	$(GLIB_CFLAGS)

test_policy_hosts_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### wifi ap utils test #######

test_wifi_ap_utils_SOURCES = \
	test-wifi-ap-utils.c

test_wifi_ap_utils_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_wifi_ap_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### secret agent interface test #######

EXTRA_DIST = test-secret-agent.py

###########################################

check-local: test-dhcp-options test-policy-hosts test-wifi-ap-utils
	$(abs_builddir)/test-dhcp-options
	$(abs_builddir)/test-policy-hosts
	$(abs_builddir)/test-wifi-ap-utils
