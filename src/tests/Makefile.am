SUBDIRS = config

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_srcdir)/src/devices \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = \
	test-general \
	test-general-with-expect \
	test-ip4-config \
	test-ip6-config \
	test-route-manager-linux \
	test-route-manager-fake \
	test-dcb \
	test-systemd \
	test-resolvconf-capture \
	test-wired-defname \
	test-utils

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

####### route manager test #######

test_route_manager_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/platform/tests \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0

test_route_manager_fake_SOURCES = \
	$(top_srcdir)/src/platform/tests/test-common.c \
	test-route-manager.c

test_route_manager_fake_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

test_route_manager_linux_SOURCES = \
	$(top_srcdir)/src/platform/tests/test-common.c \
	test-route-manager.c

test_route_manager_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/platform/tests \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1

test_route_manager_linux_LDADD = \
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

####### general-with-expect test #######

test_general_with_expect_SOURCES = \
	test-general-with-expect.c

test_general_with_expect_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### wired defname test #######

test_wired_defname_SOURCES = \
	test-wired-defname.c

test_wired_defname_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### systemd test #######

test_systemd_CFLAGS = \
	"-I$(srcdir)/../" \
	"-I$(srcdir)/../platform" \
	"-I$(srcdir)/../systemd" \
	"-I$(srcdir)/../systemd/src/systemd"

test_systemd_SOURCES = \
	test-systemd.c

test_systemd_LDADD = \
	$(top_builddir)/src/libNetworkManager-base.la \
	$(top_builddir)/src/libsystemd-nm.la

####### utils test #######

test_utils_SOURCES = \
	test-utils.c

test_utils_DEPENDENCIES = \
	$(top_srcdir)/src/NetworkManagerUtils.c

test_utils_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DPREFIX=\"/nonexistent\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DNMSTATEDIR=\"/nonsense\"

test_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

####### secret agent interface test #######

EXTRA_DIST = test-secret-agent.py

###########################################

@VALGRIND_RULES@
TESTS = \
	test-ip4-config \
	test-ip6-config \
	test-route-manager-fake \
	test-route-manager-linux \
	test-dcb \
	test-resolvconf-capture \
	test-general \
	test-general-with-expect \
	test-systemd \
	test-wired-defname \
	test-utils


if ENABLE_TESTS

check-local:
	@for t in bond bridge ethernet infiniband ip_tunnel macvlan tun veth vlan vxlan; do \
		# Ensure the device subclass factory registration constructors exist \
		# which could inadvertently break if src/Makefile.am gets changed \
		if ! LC_ALL=C nm $(top_builddir)/src/NetworkManager | LC_ALL=C grep -q "register_device_factory_internal_$$t" ; then \
			echo "Testing device factory symbols... FAILED" ; \
			exit 1 ; \
		fi \
	done
	@echo "Testing device factory symbols... PASSED"

endif

