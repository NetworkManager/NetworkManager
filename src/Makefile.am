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
	rdisc \
	supplicant-manager/tests \
	tests
endif

AM_CPPFLAGS =				\
	-I$(top_srcdir)/include		\
	-I$(top_srcdir)/libnm-core	\
	-I$(top_builddir)/libnm-core	\
	-I$(top_srcdir)/callouts	\
	-DPREFIX=\"$(prefix)\"          \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION	\
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE

# add each subdirectory that contains a libNM source file. $(sort) is being used
# primarily for its side effect of removing duplicates.
AM_CPPFLAGS += $(foreach d,$(sort $(dir $(libNetworkManager_la_SOURCES))),-I$(top_srcdir)/src/$d)

noinst_LTLIBRARIES = \
	libNetworkManager.la \
	libnm-iface-helper.la \
	libsystemd-dhcp.la

######################
# libsystemd-dhcp
######################

SYSTEMD_DHCP_CFLAGS = \
	-I$(top_srcdir)/src/dhcp-manager/systemd-dhcp/src/systemd \
	-I$(top_srcdir)/src/dhcp-manager/systemd-dhcp/src/libsystemd-network \
	-I$(top_srcdir)/src/dhcp-manager/systemd-dhcp/src/shared \
	-I$(top_srcdir)/src/dhcp-manager/systemd-dhcp

libsystemd_dhcp_la_SOURCES = \
	dhcp-manager/systemd-dhcp/src/libsystemd/sd-id128/sd-id128.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-identifier.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-identifier.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-network.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-packet.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-internal.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp6-network.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp6-lease-internal.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp6-option.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/network-internal.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/sd-dhcp-lease.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/sd-dhcp-client.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-option.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/network-internal.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/sd-dhcp6-lease.c \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-protocol.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp6-internal.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp6-protocol.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/dhcp-lease-internal.h \
	dhcp-manager/systemd-dhcp/src/libsystemd-network/sd-dhcp6-client.c \
	dhcp-manager/systemd-dhcp/src/shared/async.h \
	dhcp-manager/systemd-dhcp/src/shared/time-util.h \
	dhcp-manager/systemd-dhcp/src/shared/siphash24.h \
	dhcp-manager/systemd-dhcp/src/shared/time-util.c \
	dhcp-manager/systemd-dhcp/src/shared/socket-util.h \
	dhcp-manager/systemd-dhcp/src/shared/sparse-endian.h \
	dhcp-manager/systemd-dhcp/src/shared/macro.h \
	dhcp-manager/systemd-dhcp/src/shared/refcnt.h \
	dhcp-manager/systemd-dhcp/src/shared/util.c \
	dhcp-manager/systemd-dhcp/src/shared/in-addr-util.c \
	dhcp-manager/systemd-dhcp/src/shared/siphash24.c \
	dhcp-manager/systemd-dhcp/src/shared/util.h \
	dhcp-manager/systemd-dhcp/src/shared/in-addr-util.h \
	dhcp-manager/systemd-dhcp/src/shared/list.h \
	dhcp-manager/systemd-dhcp/src/shared/log.h \
	dhcp-manager/systemd-dhcp/src/shared/fileio.h \
	dhcp-manager/systemd-dhcp/src/shared/fileio.c \
	dhcp-manager/systemd-dhcp/src/shared/path-util.c \
	dhcp-manager/systemd-dhcp/src/shared/path-util.h \
	dhcp-manager/systemd-dhcp/src/shared/strv.h \
	dhcp-manager/systemd-dhcp/src/shared/strv.c \
	dhcp-manager/systemd-dhcp/src/shared/unaligned.h \
	dhcp-manager/systemd-dhcp/src/shared/utf8.h \
	dhcp-manager/systemd-dhcp/src/shared/utf8.c \
	dhcp-manager/systemd-dhcp/src/systemd/sd-dhcp-lease.h \
	dhcp-manager/systemd-dhcp/src/systemd/sd-dhcp-client.h \
	dhcp-manager/systemd-dhcp/src/systemd/sd-id128.h \
	dhcp-manager/systemd-dhcp/src/systemd/sd-dhcp6-lease.h \
	dhcp-manager/systemd-dhcp/src/systemd/sd-dhcp6-client.h \
	dhcp-manager/systemd-dhcp/src/systemd/sd-event.h \
	dhcp-manager/systemd-dhcp/src/systemd/_sd-common.h \
	dhcp-manager/systemd-dhcp/nm-sd-adapt.h \
	dhcp-manager/systemd-dhcp/nm-sd-adapt.c

libsystemd_dhcp_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(SYSTEMD_DHCP_CFLAGS) \
	$(GLIB_CFLAGS)

libsystemd_dhcp_la_LIBADD = \
	$(GLIB_LIBS)

###########################################
# NetworkManager
###########################################

sbin_PROGRAMS = NetworkManager

NetworkManager_SOURCES = \
	$(nm_device_sources) $(nm_device_headers) \
	$(nm_dhcp_client_sources) $(nm_dhcp_client_headers) \
	main-utils.c \
	main-utils.h \
	main.c

NetworkManager_LDADD = libNetworkManager.la

nm_device_sources = \
	devices/nm-device-bond.c \
	devices/nm-device-bridge.c \
	devices/nm-device-ethernet.c \
	devices/nm-device-gre.c \
	devices/nm-device-infiniband.c \
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
	devices/nm-device-gre.h \
	devices/nm-device-infiniband.h \
	devices/nm-device-macvlan.h \
	devices/nm-device-tun.h \
	devices/nm-device-veth.h \
	devices/nm-device-vlan.h \
	devices/nm-device-vxlan.h

nm_dhcp_client_sources = \
	dhcp-manager/nm-dhcp-dhclient.c \
	dhcp-manager/nm-dhcp-dhclient-utils.c \
	dhcp-manager/nm-dhcp-dhcpcd.c \
	dhcp-manager/nm-dhcp-systemd.c

nm_dhcp_client_headers = \
	dhcp-manager/nm-dhcp-dhclient.h \
	dhcp-manager/nm-dhcp-dhclient-utils.h \
	dhcp-manager/nm-dhcp-dhcpcd.h \
	dhcp-manager/nm-dhcp-systemd.h

nm_sources = \
	$(nm_device_headers) \
	$(nm_dhcp_client_headers) \
	devices/nm-device.c \
	devices/nm-device.h \
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
	dhcp-manager/nm-dhcp-utils.c \
	dhcp-manager/nm-dhcp-utils.h \
	dhcp-manager/nm-dhcp-listener.c \
	dhcp-manager/nm-dhcp-listener.h \
	dhcp-manager/nm-dhcp-manager.c \
	dhcp-manager/nm-dhcp-manager.h \
	\
	dns-manager/nm-dns-dnsmasq.c \
	dns-manager/nm-dns-dnsmasq.h \
	dns-manager/nm-dns-unbound.c \
	dns-manager/nm-dns-unbound.h \
	dns-manager/nm-dns-manager.c \
	dns-manager/nm-dns-manager.h \
	dns-manager/nm-dns-plugin.c \
	dns-manager/nm-dns-plugin.h \
	dns-manager/nm-dns-utils.c \
	dns-manager/nm-dns-utils.h \
	\
	dnsmasq-manager/nm-dnsmasq-manager.c \
	dnsmasq-manager/nm-dnsmasq-manager.h \
	dnsmasq-manager/nm-dnsmasq-utils.c \
	dnsmasq-manager/nm-dnsmasq-utils.h \
	\
	platform/nm-fake-platform.c \
	platform/nm-fake-platform.h \
	platform/nm-linux-platform.c \
	platform/nm-linux-platform.h \
	platform/nm-platform.c \
	platform/nm-platform.h \
	platform/wifi/wifi-utils-nl80211.c \
	platform/wifi/wifi-utils-nl80211.h \
	platform/wifi/wifi-utils-private.h \
	platform/wifi/wifi-utils.c \
	platform/wifi/wifi-utils.h \
	\
	rdisc/nm-fake-rdisc.c \
	rdisc/nm-fake-rdisc.h \
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
	settings/nm-settings.c \
	settings/nm-settings.h \
	settings/nm-system-config-interface.c \
	settings/nm-system-config-interface.h \
	\
	settings/plugins/keyfile/common.h \
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
	vpn-manager/nm-vpn-service.c \
	vpn-manager/nm-vpn-service.h \
	\
	nm-activation-request.c \
	nm-activation-request.h \
	nm-active-connection.c \
	nm-active-connection.h \
	nm-config.c \
	nm-config.h \
	nm-config-data.c \
	nm-config-data.h \
	nm-connection-provider.c \
	nm-connection-provider.h \
	nm-connectivity.c \
	nm-connectivity.h \
	nm-dbus-manager.c \
	nm-dbus-manager.h \
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
	nm-firewall-manager.c \
	nm-firewall-manager.h \
	nm-ip4-config.c \
	nm-ip4-config.h \
	nm-ip6-config.c \
	nm-ip6-config.h \
	nm-logging.c \
	nm-logging.h \
	nm-auth-manager.c \
	nm-auth-manager.h \
	nm-auth-subject.c \
	nm-auth-subject.h \
	nm-auth-utils.c \
	nm-auth-utils.h \
	nm-manager.c \
	nm-manager.h \
	nm-policy.c \
	nm-policy.h \
	nm-properties-changed-signal.c \
	nm-properties-changed-signal.h \
	nm-rfkill-manager.c \
	nm-rfkill-manager.h \
	nm-session-monitor.h \
	nm-session-monitor.c \
	nm-sleep-monitor.h \
	nm-types.h \
	NetworkManagerUtils.c \
	NetworkManagerUtils.h


if SUSPEND_RESUME_SYSTEMD
nm_sources += nm-sleep-monitor-systemd.c
else
# UPower suspend/resume used whenever systemd is not enabled
nm_sources += nm-sleep-monitor-upower.c
endif

if WITH_WEXT
nm_sources += \
	platform/wifi/wifi-utils-wext.c \
	platform/wifi/wifi-utils-wext.h
endif


GLIB_GENERATED = nm-enum-types.h nm-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include <nm-core-enum-types.h>\n'
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_enum_types_sources = $(nm_sources)

BUILT_SOURCES = $(GLIB_GENERATED)


glue_sources = \
	nm-access-point-glue.h \
	nm-active-connection-glue.h \
	nm-agent-manager-glue.h \
	nm-device-bond-glue.h \
	nm-device-bridge-glue.h \
	nm-device-ethernet-glue.h \
	nm-device-generic-glue.h \
	nm-device-glue.h \
	nm-device-gre-glue.h \
	nm-device-infiniband-glue.h \
	nm-device-macvlan-glue.h \
	nm-device-tun-glue.h \
	nm-device-veth-glue.h \
	nm-device-vlan-glue.h \
	nm-device-vxlan-glue.h \
	nm-dhcp4-config-glue.h \
	nm-dhcp6-config-glue.h \
	nm-ip4-config-glue.h \
	nm-ip6-config-glue.h \
	nm-manager-glue.h \
	nm-ppp-manager-glue.h \
	nm-settings-connection-glue.h \
	nm-settings-glue.h \
	nm-vpn-connection-glue.h

BUILT_SOURCES += $(glue_sources)

%-glue.h: $(top_srcdir)/introspection/%.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=$(subst -,_,$(subst -glue.h,,$@)) --mode=glib-server --output=$@ $<


AM_CPPFLAGS += \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(LIBNDP_CFLAGS) \
	$(LIBSOUP_CFLAGS) \
	$(SYSTEMD_LOGIN_CFLAGS) \
	$(SYSTEMD_DHCP_CFLAGS) \
	\
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DRUNDIR=\"$(rundir)\" \
	\
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\" \
	-DNMPLUGINDIR=\"$(pkglibdir)\" \
	-DNMRUNDIR=\"$(nmrundir)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\" \
	\
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\" \
	-DPPPD_PLUGIN_DIR=\"$(PPPD_PLUGIN_DIR)\" \
	\
	$(NULL)

libNetworkManager_la_SOURCES = \
	$(nm_sources) \
	$(glue_sources)

libNetworkManager_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	libsystemd-dhcp.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(SYSTEMD_LOGIN_LIBS) \
	$(LIBNDP_LIBS) \
	$(LIBDL) \
	$(LIBM)

if WITH_LIBSOUP
libNetworkManager_la_LIBADD += $(LIBSOUP_LIBS)
endif

NetworkManager_LDFLAGS = -rdynamic

######################

libnm_iface_helper_la_SOURCES = \
	dhcp-manager/nm-dhcp-client.c \
	dhcp-manager/nm-dhcp-client.h \
	dhcp-manager/nm-dhcp-utils.c \
	dhcp-manager/nm-dhcp-utils.h \
	dhcp-manager/nm-dhcp-manager.c \
	dhcp-manager/nm-dhcp-manager.h \
	\
	platform/nm-linux-platform.c \
	platform/nm-linux-platform.h \
	platform/nm-platform.c \
	platform/nm-platform.h \
	platform/wifi/wifi-utils-nl80211.c \
	platform/wifi/wifi-utils-nl80211.h \
	platform/wifi/wifi-utils-private.h \
	platform/wifi/wifi-utils.c \
	platform/wifi/wifi-utils.h \
	\
	rdisc/nm-fake-rdisc.c \
	rdisc/nm-fake-rdisc.h \
	rdisc/nm-lndp-rdisc.c \
	rdisc/nm-lndp-rdisc.h \
	rdisc/nm-rdisc.c \
	rdisc/nm-rdisc.h \
	\
	nm-route-manager.c \
	nm-route-manager.h \
	\
	nm-ip4-config.c \
	nm-ip4-config.h \
	nm-ip6-config.c \
	nm-ip6-config.h \
	\
	nm-enum-types.c \
	nm-enum-types.h \
	nm-logging.c \
	nm-logging.h \
	NetworkManagerUtils.c \
	NetworkManagerUtils.h

if WITH_WEXT
libnm_iface_helper_la_SOURCES += \
	platform/wifi/wifi-utils-wext.c \
	platform/wifi/wifi-utils-wext.h
endif

libnm_iface_helper_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	libsystemd-dhcp.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(LIBNDP_LIBS) \
	$(LIBDL) \
	$(LIBM)

libexec_PROGRAMS = nm-iface-helper

nm_iface_helper_SOURCES = \
	dhcp-manager/nm-dhcp-systemd.h \
	dhcp-manager/nm-dhcp-systemd.c \
	nm-iface-helper.c \
	main-utils.c \
	main-utils.h

nm_iface_helper_LDADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	libsystemd-dhcp.la \
	libnm-iface-helper.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(LIBNDP_LIBS) \
	$(LIBM)

nm_iface_helper_LDFLAGS = -rdynamic

######################

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = org.freedesktop.NetworkManager.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(NetworkManager_DATA)

rundir=$(localstatedir)/run/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager
install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(rundir)
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(statedir)
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(pkglibdir)

CLEANFILES = \
	$(BUILT_SOURCES) \
	settings/*-glue.h \
	devices/*-glue.h \
	devices/*/*-glue.h

