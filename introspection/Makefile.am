noinst_LTLIBRARIES = \
	libnmdbus.la

# gdbus-codegen 2.38 will emit code that requires glib 2.38, which
# will then cause availability warnings if we define
# GLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32.
#
# This is fixed in GLib 2.40 (it emits code that takes
# GLIB_VERSION_MAX_ALLOWED into account), so this workaround can go
# away when we depend on that.
AM_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(GLIB_CFLAGS))

nodist_libnmdbus_la_SOURCES = \
	nmdbus-access-point.c \
	nmdbus-access-point.h \
	nmdbus-active-connection.c \
	nmdbus-active-connection.h \
	nmdbus-agent-manager.c \
	nmdbus-agent-manager.h \
	nmdbus-device-adsl.c \
	nmdbus-device-adsl.h \
	nmdbus-device-bond.c \
	nmdbus-device-bond.h \
	nmdbus-device-bridge.c \
	nmdbus-device-bridge.h \
	nmdbus-device-bt.c \
	nmdbus-device-bt.h \
	nmdbus-device-ethernet.c \
	nmdbus-device-ethernet.h \
	nmdbus-device.c \
	nmdbus-device.h \
	nmdbus-device-generic.c \
	nmdbus-device-generic.h \
	nmdbus-device-infiniband.c \
	nmdbus-device-infiniband.h \
	nmdbus-device-ip-tunnel.c \
	nmdbus-device-ip-tunnel.h \
	nmdbus-device-macvlan.c \
	nmdbus-device-macvlan.h \
	nmdbus-device-modem.c \
	nmdbus-device-modem.h \
	nmdbus-device-olpc-mesh.c \
	nmdbus-device-olpc-mesh.h \
	nmdbus-device-team.c \
	nmdbus-device-team.h \
	nmdbus-device-tun.c \
	nmdbus-device-tun.h \
	nmdbus-device-veth.c \
	nmdbus-device-veth.h \
	nmdbus-device-vlan.c \
	nmdbus-device-vlan.h \
	nmdbus-device-vxlan.c \
	nmdbus-device-vxlan.h \
	nmdbus-device-wifi.c \
	nmdbus-device-wifi.h \
	nmdbus-device-wimax.c \
	nmdbus-device-wimax.h \
	nmdbus-dhcp4-config.c \
	nmdbus-dhcp4-config.h \
	nmdbus-dhcp6-config.c \
	nmdbus-dhcp6-config.h \
	nmdbus-ip4-config.c \
	nmdbus-ip4-config.h \
	nmdbus-ip6-config.c \
	nmdbus-ip6-config.h \
	nmdbus-manager.c \
	nmdbus-manager.h \
	nmdbus-ppp-manager.c \
	nmdbus-ppp-manager.h \
	nmdbus-secret-agent.c \
	nmdbus-secret-agent.h \
	nmdbus-settings-connection.c \
	nmdbus-settings-connection.h \
	nmdbus-settings.c \
	nmdbus-settings.h \
	nmdbus-vpn-connection.c \
	nmdbus-vpn-connection.h \
	nmdbus-vpn-plugin.c \
	nmdbus-vpn-plugin.h

DBUS_INTERFACE_DOCS = \
	nmdbus-access-point-org.freedesktop.NetworkManager.AccessPoint.xml \
	nmdbus-active-connection-org.freedesktop.NetworkManager.Connection.Active.xml \
	nmdbus-device-team-org.freedesktop.NetworkManager.Device.Team.xml \
	nmdbus-dhcp6-config-org.freedesktop.NetworkManager.DHCP6Config.xml \
	nmdbus-device-wifi-org.freedesktop.NetworkManager.Device.Wireless.xml \
	nmdbus-manager-org.freedesktop.NetworkManager.xml \
	nmdbus-vpn-connection-org.freedesktop.NetworkManager.VPN.Connection.xml \
	nmdbus-secret-agent-org.freedesktop.NetworkManager.SecretAgent.xml \
	nmdbus-device-org.freedesktop.NetworkManager.Device.xml \
	nmdbus-vpn-plugin-org.freedesktop.NetworkManager.VPN.Plugin.xml \
	nmdbus-device-bt-org.freedesktop.NetworkManager.Device.Bluetooth.xml \
	nmdbus-device-vxlan-org.freedesktop.NetworkManager.Device.Vxlan.xml \
	nmdbus-settings-connection-org.freedesktop.NetworkManager.Settings.Connection.xml \
	nmdbus-device-bond-org.freedesktop.NetworkManager.Device.Bond.xml \
	nmdbus-device-macvlan-org.freedesktop.NetworkManager.Device.Macvlan.xml \
	nmdbus-ppp-manager-org.freedesktop.NetworkManager.PPP.xml \
	nmdbus-device-vlan-org.freedesktop.NetworkManager.Device.Vlan.xml \
	nmdbus-device-adsl-org.freedesktop.NetworkManager.Device.Adsl.xml \
	nmdbus-agent-manager-org.freedesktop.NetworkManager.AgentManager.xml \
	nmdbus-device-wimax-org.freedesktop.NetworkManager.Device.WiMax.xml \
	nmdbus-device-ip-tunnel-org.freedesktop.NetworkManager.Device.IPTunnel.xml \
	nmdbus-device-tun-org.freedesktop.NetworkManager.Device.Tun.xml \
	nmdbus-device-bridge-org.freedesktop.NetworkManager.Device.Bridge.xml \
	nmdbus-device-olpc-mesh-org.freedesktop.NetworkManager.Device.OlpcMesh.xml \
	nmdbus-dhcp4-config-org.freedesktop.NetworkManager.DHCP4Config.xml \
	nmdbus-device-generic-org.freedesktop.NetworkManager.Device.Generic.xml \
	nmdbus-device-infiniband-org.freedesktop.NetworkManager.Device.Infiniband.xml \
	nmdbus-device-modem-org.freedesktop.NetworkManager.Device.Modem.xml \
	nmdbus-ip6-config-org.freedesktop.NetworkManager.IP6Config.xml \
	nmdbus-device-veth-org.freedesktop.NetworkManager.Device.Veth.xml \
	nmdbus-settings-org.freedesktop.NetworkManager.Settings.xml \
	nmdbus-device-ethernet-org.freedesktop.NetworkManager.Device.Wired.xml \
	nmdbus-ip4-config-org.freedesktop.NetworkManager.IP4Config.xml

define _make_nmdbus_rule
$(1): $(patsubst nmdbus-%.c,nm-%.xml,$(1))
	$$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $$(basename $$@) \
		--generate-docbook $$(basename $$@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$$<

$(filter $(basename $(1))-org.freedesktop.NetworkManager.%,$(DBUS_INTERFACE_DOCS)): $(1)
	@true

$(basename $(1)).h: $(1)
	@true
endef

$(foreach f,$(filter %.c,$(nodist_libnmdbus_la_SOURCES)),$(eval $(call _make_nmdbus_rule,$f)))

BUILT_SOURCES = $(nodist_libnmdbus_la_SOURCES) $(DBUS_INTERFACE_DOCS)

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = \
	nm-access-point.xml \
	nm-active-connection.xml \
	nm-agent-manager.xml \
	nm-device-adsl.xml \
	nm-device-bond.xml \
	nm-device-bridge.xml \
	nm-device-bt.xml \
	nm-device-ethernet.xml \
	nm-device-generic.xml \
	nm-device-infiniband.xml \
	nm-device-ip-tunnel.xml \
	nm-device-macvlan.xml \
	nm-device-modem.xml \
	nm-device-olpc-mesh.xml \
	nm-device-team.xml \
	nm-device-tun.xml \
	nm-device-veth.xml \
	nm-device-vlan.xml \
	nm-device-vxlan.xml \
	nm-device-wifi.xml \
	nm-device-wimax.xml \
	nm-device.xml \
	nm-dhcp4-config.xml \
	nm-dhcp6-config.xml \
	nm-ip4-config.xml \
	nm-ip6-config.xml \
	nm-manager.xml \
	nm-ppp-manager.xml \
	nm-secret-agent.xml \
	nm-settings-connection.xml \
	nm-settings.xml \
	nm-vpn-connection.xml \
	nm-vpn-plugin.xml \
	nm-wimax-nsp.xml
