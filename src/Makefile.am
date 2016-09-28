include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

SUBDIRS = \
	. \
	dhcp-manager \
	ppp-manager \
	settings/plugins \
	devices/adsl

if WITH_MODEM_MANAGER_1
SUBDIRS += devices/wwan	devices/bluetooth
endif

if WITH_WIFI
SUBDIRS += devices/wifi
endif

if WITH_TEAMDCTL
SUBDIRS += devices/team
endif

if ENABLE_TESTS
SUBDIRS += \
	dhcp-manager/tests \
	dnsmasq-manager/tests \
	platform \
	devices \
	rdisc \
	supplicant-manager/tests \
	tests
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_builddir)/introspection \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	\
	 $(foreach d,$(sort $(dir $(libNetworkManager_la_SOURCES))),-I$(top_srcdir)/src/$d) \
	\
	-DPREFIX=\"$(prefix)\"          \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	\
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DRUNSTATEDIR=\"$(runstatedir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DRUNDIR=\"$(rundir)\" \
	\
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\" \
	-DNMPLUGINDIR=\"$(pkglibdir)\" \
	-DNMRUNDIR=\"$(nmrundir)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\" \
	-DNMLIBDIR=\"$(nmlibdir)\" \
	\
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\" \
	-DPPPD_PLUGIN_DIR=\"$(PPPD_PLUGIN_DIR)\" \
	\
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(LIBNDP_CFLAGS) \
	$(LIBSOUP_CFLAGS) \
	$(SELINUX_CFLAGS) \
	$(LIBAUDIT_CFLAGS) \
	$(SYSTEMD_LOGIN_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	\
	$(NULL)

AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

sbin_PROGRAMS = \
	NetworkManager

libexec_PROGRAMS = \
	nm-iface-helper

noinst_LTLIBRARIES = \
	libNetworkManagerBase.la \
	libNetworkManager.la \
	libNetworkManagerTest.la \
	libnm-iface-helper.la \
	libsystemd-nm.la

###############################################################################

libsystemd_nm_la_SOURCES = \
	systemd/nm-sd.c \
	systemd/nm-sd.h \
	systemd/sd-adapt/nm-sd-adapt.c \
	systemd/sd-adapt/nm-sd-adapt.h \
	systemd/sd-adapt/build.h \
	systemd/sd-adapt/cgroup-util.h \
	systemd/sd-adapt/condition.h \
	systemd/sd-adapt/conf-parser.h \
	systemd/sd-adapt/def.h \
	systemd/sd-adapt/dirent-util.h \
	systemd/sd-adapt/formats-util.h \
	systemd/sd-adapt/gunicode.h \
	systemd/sd-adapt/libudev.h \
	systemd/sd-adapt/missing.h \
	systemd/sd-adapt/mkdir.h \
	systemd/sd-adapt/process-util.h \
	systemd/sd-adapt/sd-daemon.h \
	systemd/sd-adapt/stat-util.h \
	systemd/sd-adapt/udev-util.h \
	systemd/sd-adapt/udev.h \
	systemd/sd-adapt/user-util.h \
	systemd/sd-adapt/virt.h \
	systemd/src/basic/alloc-util.c \
	systemd/src/basic/alloc-util.h \
	systemd/src/basic/async.h \
	systemd/src/basic/escape.c \
	systemd/src/basic/escape.h \
	systemd/src/basic/ether-addr-util.c \
	systemd/src/basic/ether-addr-util.h \
	systemd/src/basic/extract-word.c \
	systemd/src/basic/extract-word.h \
	systemd/src/basic/fd-util.c \
	systemd/src/basic/fd-util.h \
	systemd/src/basic/fileio.c \
	systemd/src/basic/fileio.h \
	systemd/src/basic/fs-util.c \
	systemd/src/basic/fs-util.h \
	systemd/src/basic/hash-funcs.c \
	systemd/src/basic/hash-funcs.h \
	systemd/src/basic/hashmap.c \
	systemd/src/basic/hashmap.h \
	systemd/src/basic/hexdecoct.c \
	systemd/src/basic/hexdecoct.h \
	systemd/src/basic/hostname-util.c \
	systemd/src/basic/hostname-util.h \
	systemd/src/basic/in-addr-util.c \
	systemd/src/basic/in-addr-util.h \
	systemd/src/basic/io-util.c \
	systemd/src/basic/io-util.h \
	systemd/src/basic/list.h \
	systemd/src/basic/log.h \
	systemd/src/basic/macro.h \
	systemd/src/basic/mempool.c \
	systemd/src/basic/mempool.h \
	systemd/src/basic/parse-util.c \
	systemd/src/basic/parse-util.h \
	systemd/src/basic/path-util.c \
	systemd/src/basic/path-util.h \
	systemd/src/basic/prioq.c \
	systemd/src/basic/prioq.h \
	systemd/src/basic/random-util.c \
	systemd/src/basic/random-util.h \
	systemd/src/basic/refcnt.h \
	systemd/src/basic/set.h \
	systemd/src/basic/signal-util.h \
	systemd/src/basic/siphash24.c \
	systemd/src/basic/siphash24.h \
	systemd/src/basic/socket-util.c \
	systemd/src/basic/socket-util.h \
	systemd/src/basic/sparse-endian.h \
	systemd/src/basic/stdio-util.h \
	systemd/src/basic/string-table.c \
	systemd/src/basic/string-table.h \
	systemd/src/basic/string-util.c \
	systemd/src/basic/string-util.h \
	systemd/src/basic/strv.c \
	systemd/src/basic/strv.h \
	systemd/src/basic/time-util.c \
	systemd/src/basic/time-util.h \
	systemd/src/basic/umask-util.h \
	systemd/src/basic/unaligned.h \
	systemd/src/basic/utf8.c \
	systemd/src/basic/utf8.h \
	systemd/src/basic/util.c \
	systemd/src/basic/util.h \
	systemd/src/libsystemd-network/arp-util.c \
	systemd/src/libsystemd-network/arp-util.h \
	systemd/src/libsystemd-network/dhcp-identifier.c \
	systemd/src/libsystemd-network/dhcp-identifier.h \
	systemd/src/libsystemd-network/dhcp-internal.h \
	systemd/src/libsystemd-network/dhcp-lease-internal.h \
	systemd/src/libsystemd-network/dhcp-network.c \
	systemd/src/libsystemd-network/dhcp-option.c \
	systemd/src/libsystemd-network/dhcp-packet.c \
	systemd/src/libsystemd-network/dhcp-protocol.h \
	systemd/src/libsystemd-network/dhcp6-internal.h \
	systemd/src/libsystemd-network/dhcp6-lease-internal.h \
	systemd/src/libsystemd-network/dhcp6-network.c \
	systemd/src/libsystemd-network/dhcp6-option.c \
	systemd/src/libsystemd-network/dhcp6-protocol.h \
	systemd/src/libsystemd-network/lldp-internal.h \
	systemd/src/libsystemd-network/lldp-neighbor.c \
	systemd/src/libsystemd-network/lldp-neighbor.h \
	systemd/src/libsystemd-network/lldp-network.c \
	systemd/src/libsystemd-network/lldp-network.h \
	systemd/src/libsystemd-network/network-internal.c \
	systemd/src/libsystemd-network/network-internal.h \
	systemd/src/libsystemd-network/sd-dhcp-client.c \
	systemd/src/libsystemd-network/sd-dhcp-lease.c \
	systemd/src/libsystemd-network/sd-dhcp6-client.c \
	systemd/src/libsystemd-network/sd-dhcp6-lease.c \
	systemd/src/libsystemd-network/sd-ipv4acd.c \
	systemd/src/libsystemd-network/sd-ipv4ll.c \
	systemd/src/libsystemd-network/sd-lldp.c \
	systemd/src/libsystemd/sd-event/sd-event.c \
	systemd/src/libsystemd/sd-id128/id128-util.c \
	systemd/src/libsystemd/sd-id128/id128-util.h \
	systemd/src/libsystemd/sd-id128/sd-id128.c \
	systemd/src/shared/dns-domain.c \
	systemd/src/shared/dns-domain.h \
	systemd/src/systemd/_sd-common.h \
	systemd/src/systemd/sd-dhcp-client.h \
	systemd/src/systemd/sd-dhcp-lease.h \
	systemd/src/systemd/sd-dhcp6-client.h \
	systemd/src/systemd/sd-dhcp6-lease.h \
	systemd/src/systemd/sd-event.h \
	systemd/src/systemd/sd-id128.h \
	systemd/src/systemd/sd-ipv4acd.h \
	systemd/src/systemd/sd-ipv4ll.h \
	systemd/src/systemd/sd-lldp.h \
	systemd/src/systemd/sd-ndisc.h

libsystemd_nm_la_CPPFLAGS = \
	-I$(top_srcdir)/shared/ \
	-I$(top_builddir)/shared/ \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/systemd/sd-adapt/ \
	-I$(top_srcdir)/src/systemd/src/systemd/ \
	-I$(top_srcdir)/src/systemd/src/basic/ \
	-I$(top_srcdir)/src/systemd/src/shared/ \
	-I$(top_srcdir)/src/systemd/src/libsystemd-network/ \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD \
	$(GLIB_CFLAGS)

libsystemd_nm_la_LIBADD = \
	$(GLIB_LIBS)

###############################################################################

libNetworkManagerBase_la_SOURCES = \
	nm-core-utils.c \
	nm-core-utils.h \
	nm-logging.c \
	nm-logging.h

libNetworkManagerBase_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(GLIB_LIBS) \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(NULL)

###############################################################################

# These source files have a attribute((constructor)) to register their factories.
# This gets stripped out from the resulting binary if we add them to libNetworkManager.la.
# Instead, add them to the binary. An alternative would be to link with --as-needed.

nm_device_sources = \
	devices/nm-device-bond.c \
	devices/nm-device-bridge.c \
	devices/nm-device-ethernet.c \
	devices/nm-device-infiniband.c \
	devices/nm-device-ip-tunnel.c \
	devices/nm-device-macvlan.c \
	devices/nm-device-tun.c \
	devices/nm-device-veth.c \
	devices/nm-device-vlan.c \
	devices/nm-device-vxlan.c \
	$(NULL)

nm_device_headers = \
	devices/nm-device-bond.h \
	devices/nm-device-bridge.h \
	devices/nm-device-ethernet.h \
	devices/nm-device-infiniband.h \
	devices/nm-device-ip-tunnel.h \
	devices/nm-device-macvlan.h \
	devices/nm-device-tun.h \
	devices/nm-device-veth.h \
	devices/nm-device-vlan.h \
	devices/nm-device-vxlan.h \
	$(NULL)

nm_dhcp_client_sources = \
	dhcp-manager/nm-dhcp-dhclient.c \
	dhcp-manager/nm-dhcp-dhcpcd.c \
	dhcp-manager/nm-dhcp-systemd.c \
	$(NULL)

nm_dhcp_client_headers = \
	dhcp-manager/nm-dhcp-dhclient.h \
	dhcp-manager/nm-dhcp-dhcpcd.h \
	dhcp-manager/nm-dhcp-systemd.h \
	$(NULL)

###############################################################################

libNetworkManager_la_SOURCES = \
	\
	dhcp-manager/nm-dhcp-dhclient-utils.c \
	dhcp-manager/nm-dhcp-dhclient-utils.h \
	\
	nm-checkpoint-manager.c \
	nm-checkpoint-manager.h \
	nm-checkpoint.c \
	nm-checkpoint.h \
	\
	devices/nm-device.c \
	devices/nm-device.h \
	devices/nm-lldp-listener.c \
	devices/nm-lldp-listener.h \
	devices/nm-arping-manager.c \
	devices/nm-arping-manager.h \
	devices/nm-device-ethernet-utils.c \
	devices/nm-device-ethernet-utils.h \
	devices/nm-device-factory.c \
	devices/nm-device-factory.h \
	devices/nm-device-generic.c \
	devices/nm-device-generic.h \
	devices/nm-device-logging.h \
	devices/nm-device-private.h \
	\
	dhcp-manager/nm-dhcp-client.c \
	dhcp-manager/nm-dhcp-client.h \
	dhcp-manager/nm-dhcp-client-logging.h \
	dhcp-manager/nm-dhcp-helper-api.h \
	dhcp-manager/nm-dhcp-utils.c \
	dhcp-manager/nm-dhcp-utils.h \
	dhcp-manager/nm-dhcp-listener.c \
	dhcp-manager/nm-dhcp-listener.h \
	dhcp-manager/nm-dhcp-manager.c \
	dhcp-manager/nm-dhcp-manager.h \
	\
	dns-manager/nm-dns-dnsmasq.c \
	dns-manager/nm-dns-dnsmasq.h \
	dns-manager/nm-dns-systemd-resolved.c \
	dns-manager/nm-dns-systemd-resolved.h \
	dns-manager/nm-dns-unbound.c \
	dns-manager/nm-dns-unbound.h \
	dns-manager/nm-dns-manager.c \
	dns-manager/nm-dns-manager.h \
	dns-manager/nm-dns-plugin.c \
	dns-manager/nm-dns-plugin.h \
	\
	dnsmasq-manager/nm-dnsmasq-manager.c \
	dnsmasq-manager/nm-dnsmasq-manager.h \
	dnsmasq-manager/nm-dnsmasq-utils.c \
	dnsmasq-manager/nm-dnsmasq-utils.h \
	\
	platform/nmp-netns.c \
	platform/nmp-netns.h \
	platform/nmp-object.c \
	platform/nmp-object.h \
	platform/nm-platform-utils.c \
	platform/nm-platform-utils.h \
	platform/nm-platform.c \
	platform/nm-platform.h \
	platform/nm-linux-platform.c \
	platform/nm-linux-platform.h \
	platform/wifi/wifi-utils-nl80211.c \
	platform/wifi/wifi-utils-nl80211.h \
	platform/wifi/wifi-utils-private.h \
	platform/wifi/wifi-utils.c \
	platform/wifi/wifi-utils.h \
	\
	rdisc/nm-lndp-rdisc.c \
	rdisc/nm-lndp-rdisc.h \
	rdisc/nm-rdisc.c \
	rdisc/nm-rdisc.h \
	rdisc/nm-rdisc-private.h \
	\
	ppp-manager/nm-ppp-manager.c \
	ppp-manager/nm-ppp-manager.h \
	ppp-manager/nm-ppp-status.h \
	\
	settings/nm-agent-manager.c \
	settings/nm-agent-manager.h \
	settings/nm-inotify-helper.c \
	settings/nm-inotify-helper.h \
	settings/nm-secret-agent.c \
	settings/nm-secret-agent.h \
	settings/nm-settings-connection.c \
	settings/nm-settings-connection.h \
	settings/nm-settings-plugin.c \
	settings/nm-settings-plugin.h \
	settings/nm-settings.c \
	settings/nm-settings.h \
	\
	settings/plugins/keyfile/nm-keyfile-connection.c \
	settings/plugins/keyfile/nm-keyfile-connection.h \
	settings/plugins/keyfile/plugin.c \
	settings/plugins/keyfile/plugin.h \
	settings/plugins/keyfile/reader.c \
	settings/plugins/keyfile/reader.h \
	settings/plugins/keyfile/utils.c \
	settings/plugins/keyfile/utils.h \
	settings/plugins/keyfile/writer.c \
	settings/plugins/keyfile/writer.h \
	\
	supplicant-manager/nm-supplicant-config.c \
	supplicant-manager/nm-supplicant-config.h \
	supplicant-manager/nm-supplicant-interface.c \
	supplicant-manager/nm-supplicant-interface.h \
	supplicant-manager/nm-supplicant-manager.c \
	supplicant-manager/nm-supplicant-manager.h \
	supplicant-manager/nm-supplicant-settings-verify.c \
	supplicant-manager/nm-supplicant-settings-verify.h \
	supplicant-manager/nm-supplicant-types.h \
	\
	vpn-manager/nm-vpn-connection.c \
	vpn-manager/nm-vpn-connection.h \
	vpn-manager/nm-vpn-manager.c \
	vpn-manager/nm-vpn-manager.h \
	\
	nm-act-request.c \
	nm-act-request.h \
	nm-active-connection.c \
	nm-active-connection.h \
	nm-audit-manager.c \
	nm-audit-manager.h \
	nm-bus-manager.c \
	nm-bus-manager.h \
	nm-config.c \
	nm-config.h \
	nm-config-data.c \
	nm-config-data.h \
	nm-connectivity.c \
	nm-connectivity.h \
	nm-dcb.c \
	nm-dcb.h \
	nm-route-manager.c \
	nm-route-manager.h \
	nm-default-route-manager.c \
	nm-default-route-manager.h \
	nm-dhcp4-config.c \
	nm-dhcp4-config.h \
	nm-dhcp6-config.c \
	nm-dhcp6-config.h \
	nm-dispatcher.c \
	nm-dispatcher.h \
	nm-enum-types.c \
	nm-enum-types.h \
	nm-exported-object.c \
	nm-exported-object.h \
	nm-firewall-manager.c \
	nm-firewall-manager.h \
	nm-ip4-config.c \
	nm-ip4-config.h \
	nm-ip6-config.c \
	nm-ip6-config.h \
	nm-auth-manager.c \
	nm-auth-manager.h \
	nm-auth-subject.c \
	nm-auth-subject.h \
	nm-auth-utils.c \
	nm-auth-utils.h \
	nm-manager.c \
	nm-manager.h \
	nm-multi-index.c \
	nm-multi-index.h \
	nm-policy.c \
	nm-policy.h \
	nm-rfkill-manager.c \
	nm-rfkill-manager.h \
	nm-session-monitor.h \
	nm-session-monitor.c \
	nm-sleep-monitor.c \
	nm-sleep-monitor.h \
	nm-types.h \
	NetworkManagerUtils.c \
	NetworkManagerUtils.h \
	$(NULL)

if WITH_WEXT
libNetworkManager_la_SOURCES += \
	platform/wifi/wifi-utils-wext.c \
	platform/wifi/wifi-utils-wext.h
endif


libNetworkManager_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(top_builddir)/introspection/libnmdbus.la \
	libNetworkManagerBase.la \
	libsystemd-nm.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(SYSTEMD_LOGIN_LIBS) \
	$(LIBNDP_LIBS) \
	$(DL_LIBS) \
	$(LIBM) \
	$(SELINUX_LIBS) \
	$(LIBAUDIT_LIBS)

if WITH_LIBSOUP
libNetworkManager_la_LIBADD += $(LIBSOUP_LIBS)
endif

###############################################################################

libNetworkManagerTest_la_SOURCES = \
	rdisc/nm-fake-rdisc.c \
	rdisc/nm-fake-rdisc.h \
	platform/nm-fake-platform.c \
	platform/nm-fake-platform.h

libNetworkManagerTest_la_LIBADD = \
	libNetworkManager.la

###############################################################################

NetworkManager_SOURCES = \
	\
	$(nm_device_sources) \
	$(nm_device_headers) \
	\
	$(nm_dhcp_client_sources) \
	$(nm_dhcp_client_headers) \
	\
	main-utils.c \
	main-utils.h \
	main.c

NetworkManager_LDADD = \
	libNetworkManager.la

NetworkManager_LDFLAGS = \
	-rdynamic \
	-Wl,--version-script="$(srcdir)/NetworkManager.ver"

###############################################################################

libnm_iface_helper_la_SOURCES = \
	\
	dhcp-manager/nm-dhcp-client.c \
	dhcp-manager/nm-dhcp-client.h \
	dhcp-manager/nm-dhcp-client-logging.h \
	dhcp-manager/nm-dhcp-utils.c \
	dhcp-manager/nm-dhcp-utils.h \
	dhcp-manager/nm-dhcp-manager.c \
	dhcp-manager/nm-dhcp-manager.h \
	\
	platform/nmp-netns.c \
	platform/nmp-netns.h \
	platform/nmp-object.c \
	platform/nmp-object.h \
	platform/nm-platform-utils.c \
	platform/nm-platform-utils.h \
	platform/nm-platform.c \
	platform/nm-platform.h \
	platform/nm-linux-platform.c \
	platform/nm-linux-platform.h \
	platform/wifi/wifi-utils-nl80211.c \
	platform/wifi/wifi-utils-nl80211.h \
	platform/wifi/wifi-utils-private.h \
	platform/wifi/wifi-utils.c \
	platform/wifi/wifi-utils.h \
	\
	rdisc/nm-lndp-rdisc.c \
	rdisc/nm-lndp-rdisc.h \
	rdisc/nm-rdisc.c \
	rdisc/nm-rdisc.h \
	\
	nm-route-manager.c \
	nm-route-manager.h \
	\
	nm-exported-object.c \
	nm-exported-object.h \
	nm-ip4-config.c \
	nm-ip4-config.h \
	nm-ip6-config.c \
	nm-ip6-config.h \
	\
	nm-enum-types.c \
	nm-enum-types.h \
	nm-multi-index.c \
	nm-multi-index.h \
	NetworkManagerUtils.c \
	NetworkManagerUtils.h

if WITH_WEXT
libnm_iface_helper_la_SOURCES += \
	platform/wifi/wifi-utils-wext.c \
	platform/wifi/wifi-utils-wext.h
endif

libnm_iface_helper_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(top_builddir)/introspection/libnmdbus.la \
	libNetworkManagerBase.la \
	libsystemd-nm.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(LIBNDP_LIBS) \
	$(DL_LIBS) \
	$(LIBM)

nm_iface_helper_SOURCES = \
	dhcp-manager/nm-dhcp-systemd.h \
	dhcp-manager/nm-dhcp-systemd.c \
	nm-iface-helper.c \
	main-utils.c \
	main-utils.h

nm_iface_helper_LDADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	libnm-iface-helper.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(LIBNDP_LIBS) \
	$(LIBM)

nm_iface_helper_LDFLAGS = \
	-rdynamic

###############################################################################

GLIB_GENERATED = nm-enum-types.h nm-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include <nm-core-enum-types.h>\n'
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM --fhead '\#include "nm-default.h"\n'
nm_enum_types_sources = $(filter-out \
                              %/nm-device-private.h \
                              %/nm-rdisc-private.h \
                              %/wifi-utils-private.h \
                              %/nm-dhcp-client-logging.h \
                              %/nm-device-logging.h \
                              , $(libNetworkManager_la_SOURCES))

BUILT_SOURCES = $(GLIB_GENERATED)

###############################################################################

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = org.freedesktop.NetworkManager.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(NetworkManager_DATA) \
	nm-test-utils-core.h \
	NetworkManager.ver

rundir=$(runstatedir)/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager
install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(rundir)
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(statedir)
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(pkglibdir)

CLEANFILES = \
	$(BUILT_SOURCES)
