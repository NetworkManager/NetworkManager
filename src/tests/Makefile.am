AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/src/logging \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = \
	test-dhcp-options \
	test-general \
	test-ip4-config \
	test-ip6-config \
	test-dcb \
	test-resolvconf-capture

####### DHCP options test #######

test_dhcp_options_SOURCES = \
	test-dhcp-options.c

test_dhcp_options_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\"

test_dhcp_options_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### ip4 config test #######

test_ip4_config_SOURCES = \
	test-ip4-config.c

test_ip4_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### ip6 config test #######

test_ip6_config_SOURCES = \
	test-ip6-config.c

test_ip6_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### DCB test #######

test_dcb_SOURCES = \
	test-dcb.c

test_dcb_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### resolv.conf capture test #######

test_resolvconf_capture_SOURCES = \
	test-resolvconf-capture.c

test_resolvconf_capture_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### general test #######

test_general_SOURCES = \
	test-general.c

test_general_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### secret agent interface test #######

EXTRA_DIST = test-secret-agent.py

###########################################

TESTS = test-dhcp-options test-ip4-config test-ip6-config test-dcb test-resolvconf-capture test-general

