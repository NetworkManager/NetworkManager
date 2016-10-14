include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

###############################################################################

noinst_LTLIBRARIES =
CLEANFILES =
EXTRA_DIST =
BUILT_SOURCES =

SUBDIRS = \
	. \
	libnm-core \
	libnm \
	src \
	dispatcher \
	clients \
	tools \
	data \
	po \
	man \
	examples

if WITH_LEGACY_LIBRARIES
SUBDIRS += \
	libnm-util \
	libnm-glib
endif

SUBDIRS += \
	docs \
	vapi

###############################################################################

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-tests=yes \
	--with-valgrind=no \
	--enable-gtk-doc \
	--enable-more-warnings=error \
	--with-udev-dir=$$dc_install_base/lib/udev \
	--with-wext=no \
	--enable-ifcfg-rh \
	--enable-ifupdown \
	--enable-ifnet

if BUILD_SETTING_DOCS
dist-check-setting-docs:
else
dist-check-setting-docs:
	@echo "*** gobject-introspection and pygobject are needed to run 'make dist'. ***"
	@false
endif

dist: dist-check-setting-docs

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

###############################################################################

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc

###############################################################################

polkit_policydir = $(datadir)/polkit-1/actions

dist_polkit_policy_in_in_files = \
	policy/org.freedesktop.NetworkManager.policy.in.in

polkit_policy_DATA = $(dist_polkit_policy_in_in_files:.policy.in.in=.policy)

@INTLTOOL_POLICY_RULE@

DISTCLEANFILES += $(polkit_policy_DATA)

###############################################################################

noinst_LTLIBRARIES += \
	introspection/libnmdbus.la

# gdbus-codegen 2.38 will emit code that requires glib 2.38, which
# will then cause availability warnings if we define
# GLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32.
#
# This is fixed in GLib 2.40 (it emits code that takes
# GLIB_VERSION_MAX_ALLOWED into account), so this workaround can go
# away when we depend on that.
introspection_libnmdbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(GLIB_CFLAGS))

nodist_introspection_libnmdbus_la_SOURCES = \
	introspection/nmdbus-access-point.c \
	introspection/nmdbus-access-point.h \
	introspection/nmdbus-active-connection.c \
	introspection/nmdbus-active-connection.h \
	introspection/nmdbus-agent-manager.c \
	introspection/nmdbus-agent-manager.h \
	introspection/nmdbus-checkpoint.c \
	introspection/nmdbus-checkpoint.h \
	introspection/nmdbus-device-adsl.c \
	introspection/nmdbus-device-adsl.h \
	introspection/nmdbus-device-bond.c \
	introspection/nmdbus-device-bond.h \
	introspection/nmdbus-device-bridge.c \
	introspection/nmdbus-device-bridge.h \
	introspection/nmdbus-device-bt.c \
	introspection/nmdbus-device-bt.h \
	introspection/nmdbus-device-ethernet.c \
	introspection/nmdbus-device-ethernet.h \
	introspection/nmdbus-device.c \
	introspection/nmdbus-device.h \
	introspection/nmdbus-device-generic.c \
	introspection/nmdbus-device-generic.h \
	introspection/nmdbus-device-infiniband.c \
	introspection/nmdbus-device-infiniband.h \
	introspection/nmdbus-device-ip-tunnel.c \
	introspection/nmdbus-device-ip-tunnel.h \
	introspection/nmdbus-device-macvlan.c \
	introspection/nmdbus-device-macvlan.h \
	introspection/nmdbus-device-modem.c \
	introspection/nmdbus-device-modem.h \
	introspection/nmdbus-device-olpc-mesh.c \
	introspection/nmdbus-device-olpc-mesh.h \
	introspection/nmdbus-device-statistics.c \
	introspection/nmdbus-device-statistics.h \
	introspection/nmdbus-device-team.c \
	introspection/nmdbus-device-team.h \
	introspection/nmdbus-device-tun.c \
	introspection/nmdbus-device-tun.h \
	introspection/nmdbus-device-veth.c \
	introspection/nmdbus-device-veth.h \
	introspection/nmdbus-device-vlan.c \
	introspection/nmdbus-device-vlan.h \
	introspection/nmdbus-device-vxlan.c \
	introspection/nmdbus-device-vxlan.h \
	introspection/nmdbus-device-wifi.c \
	introspection/nmdbus-device-wifi.h \
	introspection/nmdbus-device-wimax.c \
	introspection/nmdbus-device-wimax.h \
	introspection/nmdbus-dhcp4-config.c \
	introspection/nmdbus-dhcp4-config.h \
	introspection/nmdbus-dhcp6-config.c \
	introspection/nmdbus-dhcp6-config.h \
	introspection/nmdbus-ip4-config.c \
	introspection/nmdbus-ip4-config.h \
	introspection/nmdbus-ip6-config.c \
	introspection/nmdbus-ip6-config.h \
	introspection/nmdbus-manager.c \
	introspection/nmdbus-manager.h \
	introspection/nmdbus-ppp-manager.c \
	introspection/nmdbus-ppp-manager.h \
	introspection/nmdbus-secret-agent.c \
	introspection/nmdbus-secret-agent.h \
	introspection/nmdbus-settings-connection.c \
	introspection/nmdbus-settings-connection.h \
	introspection/nmdbus-settings.c \
	introspection/nmdbus-settings.h \
	introspection/nmdbus-vpn-connection.c \
	introspection/nmdbus-vpn-connection.h \
	introspection/nmdbus-vpn-plugin.c \
	introspection/nmdbus-vpn-plugin.h

DBUS_INTERFACE_DOCS = \
	introspection/nmdbus-access-point-org.freedesktop.NetworkManager.AccessPoint.xml \
	introspection/nmdbus-active-connection-org.freedesktop.NetworkManager.Connection.Active.xml \
	introspection/nmdbus-checkpoint-org.freedesktop.NetworkManager.Checkpoint.xml \
	introspection/nmdbus-device-team-org.freedesktop.NetworkManager.Device.Team.xml \
	introspection/nmdbus-dhcp6-config-org.freedesktop.NetworkManager.DHCP6Config.xml \
	introspection/nmdbus-device-wifi-org.freedesktop.NetworkManager.Device.Wireless.xml \
	introspection/nmdbus-manager-org.freedesktop.NetworkManager.xml \
	introspection/nmdbus-vpn-connection-org.freedesktop.NetworkManager.VPN.Connection.xml \
	introspection/nmdbus-secret-agent-org.freedesktop.NetworkManager.SecretAgent.xml \
	introspection/nmdbus-device-org.freedesktop.NetworkManager.Device.xml \
	introspection/nmdbus-vpn-plugin-org.freedesktop.NetworkManager.VPN.Plugin.xml \
	introspection/nmdbus-device-bt-org.freedesktop.NetworkManager.Device.Bluetooth.xml \
	introspection/nmdbus-device-vxlan-org.freedesktop.NetworkManager.Device.Vxlan.xml \
	introspection/nmdbus-settings-connection-org.freedesktop.NetworkManager.Settings.Connection.xml \
	introspection/nmdbus-device-bond-org.freedesktop.NetworkManager.Device.Bond.xml \
	introspection/nmdbus-device-macvlan-org.freedesktop.NetworkManager.Device.Macvlan.xml \
	introspection/nmdbus-ppp-manager-org.freedesktop.NetworkManager.PPP.xml \
	introspection/nmdbus-device-vlan-org.freedesktop.NetworkManager.Device.Vlan.xml \
	introspection/nmdbus-device-adsl-org.freedesktop.NetworkManager.Device.Adsl.xml \
	introspection/nmdbus-agent-manager-org.freedesktop.NetworkManager.AgentManager.xml \
	introspection/nmdbus-device-wimax-org.freedesktop.NetworkManager.Device.WiMax.xml \
	introspection/nmdbus-device-ip-tunnel-org.freedesktop.NetworkManager.Device.IPTunnel.xml \
	introspection/nmdbus-device-tun-org.freedesktop.NetworkManager.Device.Tun.xml \
	introspection/nmdbus-device-bridge-org.freedesktop.NetworkManager.Device.Bridge.xml \
	introspection/nmdbus-device-olpc-mesh-org.freedesktop.NetworkManager.Device.OlpcMesh.xml \
	introspection/nmdbus-dhcp4-config-org.freedesktop.NetworkManager.DHCP4Config.xml \
	introspection/nmdbus-device-generic-org.freedesktop.NetworkManager.Device.Generic.xml \
	introspection/nmdbus-device-infiniband-org.freedesktop.NetworkManager.Device.Infiniband.xml \
	introspection/nmdbus-device-modem-org.freedesktop.NetworkManager.Device.Modem.xml \
	introspection/nmdbus-ip6-config-org.freedesktop.NetworkManager.IP6Config.xml \
	introspection/nmdbus-device-veth-org.freedesktop.NetworkManager.Device.Veth.xml \
	introspection/nmdbus-settings-org.freedesktop.NetworkManager.Settings.xml \
	introspection/nmdbus-device-ethernet-org.freedesktop.NetworkManager.Device.Wired.xml \
	introspection/nmdbus-ip4-config-org.freedesktop.NetworkManager.IP4Config.xml \
	introspection/nmdbus-device-statistics-org.freedesktop.NetworkManager.Device.Statistics.xml

define _make_nmdbus_rule
$(1): $(patsubst introspection/nmdbus-%.c,introspection/nm-%.xml,$(1))
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

$(foreach f,$(filter %.c,$(nodist_introspection_libnmdbus_la_SOURCES)),$(eval $(call _make_nmdbus_rule,$f)))

BUILT_SOURCES += $(nodist_introspection_libnmdbus_la_SOURCES) $(DBUS_INTERFACE_DOCS)

EXTRA_DIST += \
	introspection/nm-access-point.xml \
	introspection/nm-active-connection.xml \
	introspection/nm-agent-manager.xml \
	introspection/nm-checkpoint.xml \
	introspection/nm-device-adsl.xml \
	introspection/nm-device-bond.xml \
	introspection/nm-device-bridge.xml \
	introspection/nm-device-bt.xml \
	introspection/nm-device-ethernet.xml \
	introspection/nm-device-generic.xml \
	introspection/nm-device-infiniband.xml \
	introspection/nm-device-ip-tunnel.xml \
	introspection/nm-device-macvlan.xml \
	introspection/nm-device-modem.xml \
	introspection/nm-device-olpc-mesh.xml \
	introspection/nm-device-statistics.xml \
	introspection/nm-device-team.xml \
	introspection/nm-device-tun.xml \
	introspection/nm-device-veth.xml \
	introspection/nm-device-vlan.xml \
	introspection/nm-device-vxlan.xml \
	introspection/nm-device-wifi.xml \
	introspection/nm-device-wimax.xml \
	introspection/nm-device.xml \
	introspection/nm-dhcp4-config.xml \
	introspection/nm-dhcp6-config.xml \
	introspection/nm-ip4-config.xml \
	introspection/nm-ip6-config.xml \
	introspection/nm-manager.xml \
	introspection/nm-ppp-manager.xml \
	introspection/nm-secret-agent.xml \
	introspection/nm-settings-connection.xml \
	introspection/nm-settings.xml \
	introspection/nm-vpn-connection.xml \
	introspection/nm-vpn-plugin.xml \
	introspection/nm-wimax-nsp.xml

###############################################################################

EXTRA_DIST += \
	CONTRIBUTING \
	NetworkManager.pc.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	linker-script-binary.ver \
	linker-script-devices.ver \
	linker-script-settings.ver \
	Makefile.glib \
	autogen.sh \
	valgrind.suppressions \
	\
	shared/nm-common-macros.h \
	shared/nm-dbus-compat.h \
	shared/nm-default.h \
	shared/nm-dispatcher-api.h \
	shared/nm-test-libnm-utils.h \
	shared/nm-test-utils-impl.c \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-test-utils.h \
	shared/nm-utils/nm-vpn-editor-plugin-call.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-utils/unaligned.h \
	shared/nm-version-macros.h.in \
	\
	$(NULL)

CLEANFILES += \
	$(BUILT_SOURCES) \
	\
	cscope.in.out \
	cscope.out \
	cscope.po.out \
	\
	policy/*~ \
	\
	$(NULL)

###############################################################################

cscope:
	cscope -b -q -R -sshared -ssrc -slibnm-core -slibnm -slibnm-glib -slibnm-util -sclients;

###############################################################################

.PHONY: cscope
