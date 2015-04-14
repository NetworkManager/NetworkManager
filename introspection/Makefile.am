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
	nmdbus-device-gre.c \
	nmdbus-device-gre.h \
	nmdbus-device-infiniband.c \
	nmdbus-device-infiniband.h \
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

define _make_nmdbus_rule
$(1): $(patsubst nmdbus-%.c,nm-%.xml,$(1))
	$$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $$(basename $$@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$$<

$(basename $(1)).h: $(1)
	@true
endef

$(foreach f,$(filter %.c,$(nodist_libnmdbus_la_SOURCES)),$(eval $(call _make_nmdbus_rule,$f)))

CLEANFILES = $(nodist_libnmdbus_la_SOURCES)

EXTRA_DIST = \
	all.xml.in \
	generic-types.xml \
	errors.xml \
	vpn-errors.xml \
	nm-access-point.xml \
	nm-active-connection.xml \
	nm-agent-manager.xml \
	nm-device-adsl.xml \
	nm-device-bond.xml \
	nm-device-bridge.xml \
	nm-device-bt.xml \
	nm-device-ethernet.xml \
	nm-device-generic.xml \
	nm-device-gre.xml \
	nm-device-infiniband.xml \
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
