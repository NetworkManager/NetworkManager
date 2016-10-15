include $(GLIB_MAKEFILE)
-include $(INTROSPECTION_MAKEFILE)
include nm.mk

@GNOME_CODE_COVERAGE_RULES@

@NM_LOG_COMPILER@

###############################################################################

AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES =
check_LTLIBRARIES =
noinst_PROGRAMS =
check_PROGRAMS =
noinst_DATA =
sbin_PROGRAMS =
libexec_PROGRAMS =
lib_LTLIBRARIES =
pkglib_LTLIBRARIES =
CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =
dist_hook =
TESTS =
BUILT_SOURCES =
GLIB_GENERATED =
check_programs =
check_ltlibraries =
check_local =
dbusservice_DATA =

INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS =
INTROSPECTION_COMPILER_ARGS =
# Pass SANITIZER_ENV where a command that uses built libraries is
# executed, to suppress possible errors
INTROSPECTION_SCANNER_ENV = $(SANITIZER_ENV)

libnmincludedir = $(includedir)/libnm
libnminclude_HEADERS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA =

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES =

rundir=$(runstatedir)/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager

SUBDIRS = \
	. \
	src \
	dispatcher \
	clients \
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

DISTCLEANFILES += intltool-extract intltool-merge intltool-update

###############################################################################

pkgconfig_DATA += NetworkManager.pc

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

libnm_core_libnm_core_headers = \
	shared/nm-version-macros.h \
	libnm-core/nm-core-enum-types.h \
	libnm-core/nm-connection.h \
	libnm-core/nm-core-types.h \
	libnm-core/nm-dbus-interface.h \
	libnm-core/nm-errors.h \
	libnm-core/nm-setting-8021x.h \
	libnm-core/nm-setting-adsl.h \
	libnm-core/nm-setting-bluetooth.h \
	libnm-core/nm-setting-bond.h \
	libnm-core/nm-setting-bridge-port.h \
	libnm-core/nm-setting-bridge.h \
	libnm-core/nm-setting-cdma.h \
	libnm-core/nm-setting-connection.h \
	libnm-core/nm-setting-dcb.h \
	libnm-core/nm-setting-generic.h \
	libnm-core/nm-setting-gsm.h \
	libnm-core/nm-setting-infiniband.h \
	libnm-core/nm-setting-ip-config.h \
	libnm-core/nm-setting-ip-tunnel.h \
	libnm-core/nm-setting-ip4-config.h \
	libnm-core/nm-setting-ip6-config.h \
	libnm-core/nm-setting-macvlan.h \
	libnm-core/nm-setting-olpc-mesh.h \
	libnm-core/nm-setting-ppp.h \
	libnm-core/nm-setting-pppoe.h \
	libnm-core/nm-setting-proxy.h \
	libnm-core/nm-setting-serial.h \
	libnm-core/nm-setting-team-port.h \
	libnm-core/nm-setting-team.h \
	libnm-core/nm-setting-tun.h \
	libnm-core/nm-setting-vlan.h \
	libnm-core/nm-setting-vpn.h \
	libnm-core/nm-setting-vxlan.h \
	libnm-core/nm-setting-wimax.h \
	libnm-core/nm-setting-wired.h \
	libnm-core/nm-setting-wireless-security.h \
	libnm-core/nm-setting-wireless.h \
	libnm-core/nm-setting.h \
	libnm-core/nm-simple-connection.h \
	libnm-core/nm-utils.h \
	libnm-core/nm-version.h \
	libnm-core/nm-vpn-dbus-interface.h \
	libnm-core/nm-vpn-editor-plugin.h \
	libnm-core/nm-vpn-plugin-info.h

libnm_core_libnm_core_private_headers = \
	shared/nm-utils/nm-shared-utils.h \
	libnm-core/crypto.h \
	libnm-core/nm-connection-private.h \
	libnm-core/nm-core-internal.h \
	libnm-core/nm-core-types-internal.h \
	libnm-core/nm-keyfile-internal.h \
	libnm-core/nm-keyfile-utils.h \
	libnm-core/nm-property-compare.h \
	libnm-core/nm-setting-private.h \
	libnm-core/nm-utils-private.h

libnm_core_libnm_core_sources = \
	shared/nm-utils/nm-shared-utils.c \
	libnm-core/nm-core-enum-types.c \
	libnm-core/crypto.c \
	libnm-core/nm-connection.c \
	libnm-core/nm-dbus-utils.c \
	libnm-core/nm-errors.c \
	libnm-core/nm-keyfile-reader.c \
	libnm-core/nm-keyfile-utils.c \
	libnm-core/nm-keyfile-writer.c \
	libnm-core/nm-property-compare.c \
	libnm-core/nm-setting-8021x.c \
	libnm-core/nm-setting-adsl.c \
	libnm-core/nm-setting-bluetooth.c \
	libnm-core/nm-setting-bond.c \
	libnm-core/nm-setting-bridge-port.c \
	libnm-core/nm-setting-bridge.c \
	libnm-core/nm-setting-cdma.c \
	libnm-core/nm-setting-connection.c \
	libnm-core/nm-setting-dcb.c \
	libnm-core/nm-setting-generic.c \
	libnm-core/nm-setting-gsm.c \
	libnm-core/nm-setting-infiniband.c \
	libnm-core/nm-setting-ip-config.c \
	libnm-core/nm-setting-ip-tunnel.c \
	libnm-core/nm-setting-ip4-config.c \
	libnm-core/nm-setting-ip6-config.c \
	libnm-core/nm-setting-macvlan.c \
	libnm-core/nm-setting-olpc-mesh.c \
	libnm-core/nm-setting-ppp.c \
	libnm-core/nm-setting-pppoe.c \
	libnm-core/nm-setting-proxy.c \
	libnm-core/nm-setting-serial.c \
	libnm-core/nm-setting-team-port.c \
	libnm-core/nm-setting-team.c \
	libnm-core/nm-setting-tun.c \
	libnm-core/nm-setting-vlan.c \
	libnm-core/nm-setting-vpn.c \
	libnm-core/nm-setting-vxlan.c \
	libnm-core/nm-setting-wimax.c \
	libnm-core/nm-setting-wired.c \
	libnm-core/nm-setting-wireless-security.c \
	libnm-core/nm-setting-wireless.c \
	libnm-core/nm-setting.c \
	libnm-core/nm-simple-connection.c \
	libnm-core/nm-utils.c \
	libnm-core/nm-vpn-editor-plugin.c \
	libnm-core/nm-vpn-plugin-info.c

libnminclude_HEADERS += $(libnm_core_libnm_core_headers)

###############################################################################

noinst_LTLIBRARIES += libnm-core/libnm-core.la

GLIB_GENERATED += \
	libnm-core/nm-core-enum-types.h \
	libnm-core/nm-core-enum-types.c

nm_core_enum_types_sources = $(filter-out %nm-core-enum-types.h,$(libnm_core_libnm_core_headers))
nm_core_enum_types_MKENUMS_H_FLAGS = --identifier-prefix NM
nm_core_enum_types_MKENUMS_C_FLAGS = --identifier-prefix NM

libnm_core_libnm_core_la_CPPFLAGS = \
	-I${srcdir}/shared \
	-I${builddir}/shared \
	-I${srcdir}/libnm-core \
	-I${builddir}/libnm-core \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMLIBDIR=\"$(nmlibdir)\" \
	-DNMPLUGINDIR=\"$(pkglibdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	$(JANSSON_CFLAGS)

libnm_core_libnm_core_la_SOURCES = \
	$(libnm_core_libnm_core_sources) \
	$(libnm_core_libnm_core_private_headers)

libnm_core_libnm_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(UUID_LIBS) \
	$(JANSSON_LIBS)

libnm_core_libnm_core_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS)

if WITH_GNUTLS
libnm_core_libnm_core_la_CPPFLAGS += $(GNUTLS_CFLAGS)
libnm_core_libnm_core_la_SOURCES += libnm-core/crypto_gnutls.c
libnm_core_libnm_core_la_LIBADD += $(GNUTLS_LIBS)
endif

if WITH_NSS
libnm_core_libnm_core_la_CPPFLAGS += $(NSS_CFLAGS)
libnm_core_libnm_core_la_SOURCES += libnm-core/crypto_nss.c
libnm_core_libnm_core_la_LIBADD += $(NSS_LIBS)
endif

libnm-core/nm-vpn-dbus-types.xml: libnm-core/nm-vpn-dbus-interface.h tools/enums-to-docbook.pl
	$(AM_V_GEN) @PERL@ $(srcdir)/tools/enums-to-docbook.pl 'nm-vpn-dbus-types' 'VPN Plugin D-Bus API Types' $^ >$@

libnm-core/nm-dbus-types.xml: libnm-core/nm-dbus-interface.h tools/enums-to-docbook.pl
	$(AM_V_GEN) @PERL@ $(srcdir)/tools/enums-to-docbook.pl 'nm-dbus-types' 'NetworkManager D-Bus API Types' $^ >$@

BUILT_SOURCES += \
	libnm-core/nm-vpn-dbus-types.xml \
	libnm-core/nm-dbus-types.xml

###############################################################################

libnm_core_tests_programs = \
	libnm-core/tests/test-compare \
	libnm-core/tests/test-crypto \
	libnm-core/tests/test-general \
	libnm-core/tests/test-keyfile \
	libnm-core/tests/test-secrets \
	libnm-core/tests/test-setting-8021x \
	libnm-core/tests/test-setting-bond \
	libnm-core/tests/test-setting-dcb \
	libnm-core/tests/test-settings-defaults

check_programs += $(libnm_core_tests_programs)

GLIB_GENERATED += \
	libnm-core/tests/nm-core-tests-enum-types.h \
	libnm-core/tests/nm-core-tests-enum-types.c

nm_core_tests_enum_types_sources = libnm-core/tests/test-general-enums.h
nm_core_tests_enum_types_MKENUMS_H_FLAGS = --identifier-prefix NM
nm_core_tests_enum_types_MKENUMS_C_FLAGS = --identifier-prefix NM

libnm_core_tests_cppflags = \
	-I${srcdir}/shared \
	-I${builddir}/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm-core/tests \
	-DNETWORKMANAGER_COMPILATION \
	$(GLIB_CFLAGS) \
	-DTEST_CERT_DIR=\"$(abs_srcdir)/libnm-core/tests/certs\"

libnm_core_tests_test_compare_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_crypto_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_general_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_keyfile_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_secrets_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_setting_8021x_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_setting_bond_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_setting_dcb_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_settings_defaults_CPPFLAGS = $(libnm_core_tests_cppflags)

libnm_core_tests_test_general_SOURCES = \
	libnm-core/tests/nm-core-tests-enum-types.c \
	libnm-core/tests/nm-core-tests-enum-types.h \
	libnm-core/tests/test-general-enums.h \
	libnm-core/tests/test-general.c

libnm_core_tests_ldadd = \
	libnm-core/libnm-core.la \
	$(GLIB_LIBS)

libnm_core_tests_test_compare_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_crypto_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_general_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_keyfile_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_secrets_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_setting_8021x_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_setting_bond_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_setting_dcb_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_settings_defaults_LDADD = $(libnm_core_tests_ldadd)

# test-cert.p12 created with:
#
# openssl pkcs12 -export \
#	-in test_key_and_cert.pem \
#	-inkey test_key_and_cert.pem \
#	-certfile test_ca_cert.pem \
#	-name "test-pkcs12" \
#	-out test-cert.p12

EXTRA_DIST += \
	libnm-core/tests/certs/ca-no-ending-newline.pem \
	libnm-core/tests/certs/pkcs8-decrypted.der \
	libnm-core/tests/certs/pkcs8-enc-key.pem \
	libnm-core/tests/certs/pkcs8-noenc-key.pem \
	libnm-core/tests/certs/test2_ca_cert.pem \
	libnm-core/tests/certs/test2-cert.p12 \
	libnm-core/tests/certs/test2_key_and_cert.pem \
	libnm-core/tests/certs/test-aes-key.pem \
	libnm-core/tests/certs/test_ca_cert.der \
	libnm-core/tests/certs/test_ca_cert.pem \
	libnm-core/tests/certs/test-ca-cert.pem \
	libnm-core/tests/certs/test-cert.p12 \
	libnm-core/tests/certs/test_key_and_cert.pem \
	libnm-core/tests/certs/test-key-and-cert.pem \
	libnm-core/tests/certs/test-key-only-decrypted.der \
	libnm-core/tests/certs/test-key-only-decrypted.pem \
	libnm-core/tests/certs/test-key-only.pem

###############################################################################

libnminclude_headers = \
	shared/nm-version-macros.h \
	libnm/NetworkManager.h \
	libnm/nm-access-point.h \
	libnm/nm-active-connection.h \
	libnm/nm-client.h \
	libnm/nm-device-adsl.h \
	libnm/nm-device-bond.h \
	libnm/nm-device-bridge.h \
	libnm/nm-device-bt.h \
	libnm/nm-device-ethernet.h \
	libnm/nm-device-generic.h \
	libnm/nm-device-infiniband.h \
	libnm/nm-device-ip-tunnel.h \
	libnm/nm-device-macvlan.h \
	libnm/nm-device-modem.h \
	libnm/nm-device-olpc-mesh.h \
	libnm/nm-device-team.h \
	libnm/nm-device-tun.h \
	libnm/nm-device-vlan.h \
	libnm/nm-device-vxlan.h \
	libnm/nm-device-wifi.h \
	libnm/nm-device-wimax.h \
	libnm/nm-device.h \
	libnm/nm-dhcp-config.h \
	libnm/nm-enum-types.h \
	libnm/nm-ip-config.h \
	libnm/nm-object.h \
	libnm/nm-remote-connection.h \
	libnm/nm-types.h \
	libnm/nm-vpn-connection.h \
	libnm/nm-vpn-editor.h \
	libnm/nm-wimax-nsp.h

libnminclude_nointrospect_headers = \
	libnm/nm-secret-agent-old.h \
	libnm/nm-vpn-plugin-old.h \
	libnm/nm-vpn-service-plugin.h

libnminclude_HEADERS += \
	$(libnminclude_headers) \
	$(libnminclude_nointrospect_headers)

###############################################################################

lib_LTLIBRARIES += libnm/libnm.la

GLIB_GENERATED += \
	libnm/nm-enum-types.h \
	libnm/nm-enum-types.c

nm_enum_types_sources = \
	$(libnminclude_headers) \
	$(libnminclude_nointrospect_headers)
nm_enum_types_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include <nm-core-enum-types.h>\n'
nm_enum_types_MKENUMS_C_FLAGS = --identifier-prefix NM --fhead '\#include "nm-default.h"\n'

libnm_libnm_la_CPPFLAGS = \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(builddir)/introspection \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DNMRUNDIR=\"$(nmrundir)\" \
	$(CODE_COVERAGE_CFLAGS)

libnm_libnm_la_private_headers = \
	libnm/nm-dbus-helpers.h \
	libnm/nm-device-private.h \
	libnm/nm-dhcp4-config.h \
	libnm/nm-dhcp6-config.h \
	libnm/nm-ip4-config.h \
	libnm/nm-ip6-config.h \
	libnm/nm-manager.h \
	libnm/nm-object-cache.h \
	libnm/nm-object-private.h \
	libnm/nm-remote-connection-private.h \
	libnm/nm-remote-settings.h

libnm_libnm_la_sources = \
	libnm/nm-access-point.c \
	libnm/nm-active-connection.c \
	libnm/nm-client.c \
	libnm/nm-dbus-helpers.c \
	libnm/nm-device-adsl.c \
	libnm/nm-device-bond.c \
	libnm/nm-device-bridge.c \
	libnm/nm-device-bt.c \
	libnm/nm-device-ethernet.c \
	libnm/nm-device-generic.c \
	libnm/nm-device-infiniband.c \
	libnm/nm-device-ip-tunnel.c \
	libnm/nm-device-macvlan.c \
	libnm/nm-device-modem.c \
	libnm/nm-device-olpc-mesh.c \
	libnm/nm-device-team.c \
	libnm/nm-device-tun.c \
	libnm/nm-device-vlan.c \
	libnm/nm-device-vxlan.c \
	libnm/nm-device-wifi.c \
	libnm/nm-device-wimax.c \
	libnm/nm-device.c \
	libnm/nm-dhcp-config.c \
	libnm/nm-dhcp4-config.c \
	libnm/nm-dhcp6-config.c \
	libnm/nm-enum-types.c \
	libnm/nm-ip-config.c \
	libnm/nm-ip4-config.c \
	libnm/nm-ip6-config.c \
	libnm/nm-manager.c \
	libnm/nm-object-cache.c \
	libnm/nm-object.c \
	libnm/nm-remote-connection.c \
	libnm/nm-remote-settings.c \
	libnm/nm-secret-agent-old.c \
	libnm/nm-vpn-connection.c \
	libnm/nm-vpn-plugin-old.c \
	libnm/nm-vpn-editor.c \
	libnm/nm-vpn-service-plugin.c \
	libnm/nm-wimax-nsp.c

libnm_libnm_la_SOURCES = \
	$(libnm_libnm_la_sources) \
	$(libnm_libnm_la_private_headers)

EXTRA_libnm_libnm_la_DEPENDENCIES = \
	libnm/libnm.ver

libnm_libnm_la_LIBADD = \
	libnm-core/libnm-core.la \
	introspection/libnmdbus.la \
	$(DL_LIBS) \
	$(GLIB_LIBS) \
	$(UUID_LIBS) \
	$(GUDEV_LIBS)

libnm_libnm_la_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/libnm/libnm.ver" \
	$(CODE_COVERAGE_LDFLAGS) \
	-version-info "1:0:1"

check-local-exports-libnm: libnm/libnm.la
	$(srcdir)/tools/check-exports.sh "$(builddir)/libnm/.libs/libnm.so" "$(srcdir)/libnm/libnm.ver"

check_local += check-local-exports-libnm

pkgconfig_DATA += libnm/libnm.pc

DISTCLEANFILES += \
	libnm/libnm.pc

EXTRA_DIST += \
	libnm/libnm.pc.in \
	libnm/libnm.ver


INTROSPECTION_COMPILER_ARGS += \
	--includedir=$(srcdir)/libnm-core \
	--includedir=$(builddir)/libnm-core \
	--includedir=$(srcdir)/libnm \
	--includedir=$(builddir)/libnm

if HAVE_INTROSPECTION
introspection_sources = \
	$(libnm_core_libnm_core_headers) \
	$(libnminclude_headers) \
	$(libnm_core_libnm_core_sources) \
	$(libnm_libnm_la_sources)

libnm/NM-1.0.gir: libnm/libnm.la
libnm_NM_1_0_gir_INCLUDES = Gio-2.0
libnm_NM_1_0_gir_PACKAGES = gio-2.0 gudev-1.0
libnm_NM_1_0_gir_EXPORT_PACKAGES = libnm
libnm_NM_1_0_gir_CFLAGS = $(libnm_libnm_la_CPPFLAGS)
libnm_NM_1_0_gir_LIBS = libnm/libnm.la
libnm_NM_1_0_gir_FILES = $(introspection_sources)
libnm_NM_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm
INTROSPECTION_GIRS += libnm/NM-1.0.gir

endif

if BUILD_SETTING_DOCS

libnm_noinst_data = \
	libnm/nm-property-docs.xml \
	libnm/nm-setting-docs-overrides.xml \
	libnm/nm-setting-docs.xml \
	libnm/nm-keyfile-docs.xml \
	libnm/nm-ifcfg-rh-docs.xml

noinst_DATA += $(libnm_noinst_data)

libnm_docs_sources = $(filter-out %/nm-core-enum-types.c,$(libnm_core_libnm_core_sources))

libnm/nm-setting-docs-overrides.xml: libnm/generate-plugin-docs.pl $(libnm_docs_sources)
	$(srcdir)/libnm/generate-plugin-docs.pl dbus "$(top_srcdir)" $@

# When the python scripts loads libnm and the address sanitizers is
# enabled, we must LD_PRELOAD libasan otherwise it will complain that
# it was not loaded as initial library.
libnm/nm-property-docs.xml: libnm/generate-setting-docs.py $(libnm_docs_sources) | libnm/NM-1.0.gir libnm/NM-1.0.typelib libnm/libnm.la
	export GI_TYPELIB_PATH=$(abs_builddir)/libnm$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}; \
	export LD_LIBRARY_PATH=$(abs_builddir)/libnm/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}; \
	$(call set_sanitizer_env,$(abs_builddir)/libnm/.libs/libnm.so); \
	$(srcdir)/libnm/generate-setting-docs.py \
		--gir $(builddir)/libnm/NM-1.0.gir \
		--output $@

libnm/nm-setting-docs.xml: libnm/generate-setting-docs.py $(libnm_docs_sources) libnm/nm-setting-docs-overrides.xml | libnm/NM-1.0.gir libnm/NM-1.0.typelib libnm/libnm.la
	export GI_TYPELIB_PATH=$(abs_builddir)/libnm$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}; \
	export LD_LIBRARY_PATH=$(abs_builddir)/libnm/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}; \
	$(call set_sanitizer_env,$(abs_builddir)/libnm/.libs/libnm.so); \
	$(srcdir)/libnm/generate-setting-docs.py \
		--gir $(builddir)/libnm/NM-1.0.gir \
		--overrides $(builddir)/libnm/nm-setting-docs-overrides.xml \
		--output $@

libnm/nm-keyfile-docs.xml: libnm/generate-plugin-docs.pl $(libnm_docs_sources)
	$(srcdir)/libnm/generate-plugin-docs.pl keyfile "$(top_srcdir)" $@
libnm/nm-ifcfg-rh-docs.xml: libnm/generate-plugin-docs.pl $(libnm_docs_sources)
	$(srcdir)/libnm/generate-plugin-docs.pl ifcfg-rh "$(top_srcdir)" $@

EXTRA_DIST += $(libnm_noinst_data)

endif

EXTRA_DIST += \
	libnm/generate-setting-docs.py \
	libnm/generate-plugin-docs.pl

###############################################################################

libnm_tests_programs = \
	libnm/tests/test-nm-client \
	libnm/tests/test-remote-settings-client \
	libnm/tests/test-secret-agent

check_programs += $(libnm_tests_programs)

libnm_tests_cppflags = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm \
	-I$(top_builddir)/libnm \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	-DTEST_NM_SERVICE=\"$(abs_top_srcdir)/tools/test-networkmanager-service.py\" \
	$(GLIB_CFLAGS)

libnm_tests_ldadd = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)

libnm_tests_test_nm_client_CPPFLAGS = $(libnm_tests_cppflags)
libnm_tests_test_remote_settings_client_CPPFLAGS = $(libnm_tests_cppflags)
libnm_tests_test_secret_agent_CPPFLAGS = $(libnm_tests_cppflags)

libnm_tests_test_nm_client_SOURCES = \
	shared/nm-test-utils-impl.c \
	shared/nm-test-libnm-utils.h \
	libnm/tests/test-nm-client.c

libnm_tests_test_remote_settings_client_SOURCES = \
	shared/nm-test-utils-impl.c \
	shared/nm-test-libnm-utils.h \
	libnm/tests/test-remote-settings-client.c

libnm_tests_test_secret_agent_SOURCES = \
	shared/nm-test-utils-impl.c \
	shared/nm-test-libnm-utils.h \
	libnm/tests/test-secret-agent.c

libnm_tests_test_nm_client_LDADD = $(libnm_tests_ldadd)
libnm_tests_test_remote_settings_client_LDADD = $(libnm_tests_ldadd)
libnm_tests_test_secret_agent_LDADD = $(libnm_tests_ldadd)

###############################################################################

# just test, that we can build "nm-vpn-plugin-utils.c"

check_ltlibraries += libnm/tests/libnm-vpn-plugin-utils-test.la

libnm_tests_libnm_vpn_plugin_utils_test_la_SOURCES = \
     shared/nm-utils/nm-vpn-plugin-utils.c \
     shared/nm-utils/nm-vpn-plugin-utils.h

libnm_tests_libnm_vpn_plugin_utils_test_la_CFLAGS = \
    $(GLIB_CFLAGS) \
    -I$(srcdir)/shared \
    -I$(srcdir)/libnm-core \
    -I$(srcdir)/libnm

libnm_tests_libnm_vpn_plugin_utils_test_la_LIBADD = \
    $(GLIB_LIBS)

###############################################################################
# src/
###############################################################################

src_cppflags = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_builddir)/introspection \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	\
	 $(foreach d,$(sort $(dir $(src_libNetworkManager_la_SOURCES))),-I$(srcdir)/$d) \
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

src_ldflags = $(CODE_COVERAGE_LDFLAGS)

sbin_PROGRAMS += \
	src/NetworkManager

libexec_PROGRAMS += \
	src/nm-iface-helper

noinst_LTLIBRARIES += \
	src/libNetworkManagerBase.la \
	src/libNetworkManager.la \
	src/libsystemd-nm.la

check_ltlibraries += src/libNetworkManagerTest.la

###############################################################################

src_libsystemd_nm_la_SOURCES = \
	src/systemd/nm-sd.c \
	src/systemd/nm-sd.h \
	src/systemd/sd-adapt/nm-sd-adapt.c \
	src/systemd/sd-adapt/nm-sd-adapt.h \
	src/systemd/sd-adapt/build.h \
	src/systemd/sd-adapt/cgroup-util.h \
	src/systemd/sd-adapt/condition.h \
	src/systemd/sd-adapt/conf-parser.h \
	src/systemd/sd-adapt/def.h \
	src/systemd/sd-adapt/dirent-util.h \
	src/systemd/sd-adapt/formats-util.h \
	src/systemd/sd-adapt/gunicode.h \
	src/systemd/sd-adapt/libudev.h \
	src/systemd/sd-adapt/missing.h \
	src/systemd/sd-adapt/mkdir.h \
	src/systemd/sd-adapt/process-util.h \
	src/systemd/sd-adapt/sd-daemon.h \
	src/systemd/sd-adapt/stat-util.h \
	src/systemd/sd-adapt/udev-util.h \
	src/systemd/sd-adapt/udev.h \
	src/systemd/sd-adapt/user-util.h \
	src/systemd/sd-adapt/virt.h \
	src/systemd/src/basic/alloc-util.c \
	src/systemd/src/basic/alloc-util.h \
	src/systemd/src/basic/async.h \
	src/systemd/src/basic/escape.c \
	src/systemd/src/basic/escape.h \
	src/systemd/src/basic/ether-addr-util.c \
	src/systemd/src/basic/ether-addr-util.h \
	src/systemd/src/basic/extract-word.c \
	src/systemd/src/basic/extract-word.h \
	src/systemd/src/basic/fd-util.c \
	src/systemd/src/basic/fd-util.h \
	src/systemd/src/basic/fileio.c \
	src/systemd/src/basic/fileio.h \
	src/systemd/src/basic/fs-util.c \
	src/systemd/src/basic/fs-util.h \
	src/systemd/src/basic/hash-funcs.c \
	src/systemd/src/basic/hash-funcs.h \
	src/systemd/src/basic/hashmap.c \
	src/systemd/src/basic/hashmap.h \
	src/systemd/src/basic/hexdecoct.c \
	src/systemd/src/basic/hexdecoct.h \
	src/systemd/src/basic/hostname-util.c \
	src/systemd/src/basic/hostname-util.h \
	src/systemd/src/basic/in-addr-util.c \
	src/systemd/src/basic/in-addr-util.h \
	src/systemd/src/basic/io-util.c \
	src/systemd/src/basic/io-util.h \
	src/systemd/src/basic/list.h \
	src/systemd/src/basic/log.h \
	src/systemd/src/basic/macro.h \
	src/systemd/src/basic/mempool.c \
	src/systemd/src/basic/mempool.h \
	src/systemd/src/basic/parse-util.c \
	src/systemd/src/basic/parse-util.h \
	src/systemd/src/basic/path-util.c \
	src/systemd/src/basic/path-util.h \
	src/systemd/src/basic/prioq.c \
	src/systemd/src/basic/prioq.h \
	src/systemd/src/basic/random-util.c \
	src/systemd/src/basic/random-util.h \
	src/systemd/src/basic/refcnt.h \
	src/systemd/src/basic/set.h \
	src/systemd/src/basic/signal-util.h \
	src/systemd/src/basic/siphash24.c \
	src/systemd/src/basic/siphash24.h \
	src/systemd/src/basic/socket-util.c \
	src/systemd/src/basic/socket-util.h \
	src/systemd/src/basic/sparse-endian.h \
	src/systemd/src/basic/stdio-util.h \
	src/systemd/src/basic/string-table.c \
	src/systemd/src/basic/string-table.h \
	src/systemd/src/basic/string-util.c \
	src/systemd/src/basic/string-util.h \
	src/systemd/src/basic/strv.c \
	src/systemd/src/basic/strv.h \
	src/systemd/src/basic/time-util.c \
	src/systemd/src/basic/time-util.h \
	src/systemd/src/basic/umask-util.h \
	src/systemd/src/basic/unaligned.h \
	src/systemd/src/basic/utf8.c \
	src/systemd/src/basic/utf8.h \
	src/systemd/src/basic/util.c \
	src/systemd/src/basic/util.h \
	src/systemd/src/libsystemd-network/arp-util.c \
	src/systemd/src/libsystemd-network/arp-util.h \
	src/systemd/src/libsystemd-network/dhcp-identifier.c \
	src/systemd/src/libsystemd-network/dhcp-identifier.h \
	src/systemd/src/libsystemd-network/dhcp-internal.h \
	src/systemd/src/libsystemd-network/dhcp-lease-internal.h \
	src/systemd/src/libsystemd-network/dhcp-network.c \
	src/systemd/src/libsystemd-network/dhcp-option.c \
	src/systemd/src/libsystemd-network/dhcp-packet.c \
	src/systemd/src/libsystemd-network/dhcp-protocol.h \
	src/systemd/src/libsystemd-network/dhcp6-internal.h \
	src/systemd/src/libsystemd-network/dhcp6-lease-internal.h \
	src/systemd/src/libsystemd-network/dhcp6-network.c \
	src/systemd/src/libsystemd-network/dhcp6-option.c \
	src/systemd/src/libsystemd-network/dhcp6-protocol.h \
	src/systemd/src/libsystemd-network/lldp-internal.h \
	src/systemd/src/libsystemd-network/lldp-neighbor.c \
	src/systemd/src/libsystemd-network/lldp-neighbor.h \
	src/systemd/src/libsystemd-network/lldp-network.c \
	src/systemd/src/libsystemd-network/lldp-network.h \
	src/systemd/src/libsystemd-network/network-internal.c \
	src/systemd/src/libsystemd-network/network-internal.h \
	src/systemd/src/libsystemd-network/sd-dhcp-client.c \
	src/systemd/src/libsystemd-network/sd-dhcp-lease.c \
	src/systemd/src/libsystemd-network/sd-dhcp6-client.c \
	src/systemd/src/libsystemd-network/sd-dhcp6-lease.c \
	src/systemd/src/libsystemd-network/sd-ipv4acd.c \
	src/systemd/src/libsystemd-network/sd-ipv4ll.c \
	src/systemd/src/libsystemd-network/sd-lldp.c \
	src/systemd/src/libsystemd/sd-event/sd-event.c \
	src/systemd/src/libsystemd/sd-id128/id128-util.c \
	src/systemd/src/libsystemd/sd-id128/id128-util.h \
	src/systemd/src/libsystemd/sd-id128/sd-id128.c \
	src/systemd/src/shared/dns-domain.c \
	src/systemd/src/shared/dns-domain.h \
	src/systemd/src/systemd/_sd-common.h \
	src/systemd/src/systemd/sd-dhcp-client.h \
	src/systemd/src/systemd/sd-dhcp-lease.h \
	src/systemd/src/systemd/sd-dhcp6-client.h \
	src/systemd/src/systemd/sd-dhcp6-lease.h \
	src/systemd/src/systemd/sd-event.h \
	src/systemd/src/systemd/sd-id128.h \
	src/systemd/src/systemd/sd-ipv4acd.h \
	src/systemd/src/systemd/sd-ipv4ll.h \
	src/systemd/src/systemd/sd-lldp.h \
	src/systemd/src/systemd/sd-ndisc.h

src_libsystemd_nm_la_CPPFLAGS = \
	-I$(top_srcdir)/shared/ \
	-I$(top_builddir)/shared/ \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(srcdir)/src \
	-I$(top_srcdir)/src/systemd/sd-adapt/ \
	-I$(top_srcdir)/src/systemd/src/systemd/ \
	-I$(top_srcdir)/src/systemd/src/basic/ \
	-I$(top_srcdir)/src/systemd/src/shared/ \
	-I$(top_srcdir)/src/systemd/src/libsystemd-network/ \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD \
	$(GLIB_CFLAGS)

src_libsystemd_nm_la_LIBADD = \
	$(GLIB_LIBS)

###############################################################################

src_libNetworkManagerBase_la_CPPFLAGS = $(src_cppflags)

src_libNetworkManagerBase_la_SOURCES = \
	src/nm-core-utils.c \
	src/nm-core-utils.h \
	src/nm-logging.c \
	src/nm-logging.h

src_libNetworkManagerBase_la_LIBADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(GLIB_LIBS) \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(NULL)

###############################################################################

src_libNetworkManager_la_CPPFLAGS = $(src_cppflags)

src_libNetworkManager_la_SOURCES = \
	\
	src/nm-checkpoint-manager.c \
	src/nm-checkpoint-manager.h \
	src/nm-checkpoint.c \
	src/nm-checkpoint.h \
	\
	src/devices/nm-device.c \
	src/devices/nm-device.h \
	src/devices/nm-lldp-listener.c \
	src/devices/nm-lldp-listener.h \
	src/devices/nm-arping-manager.c \
	src/devices/nm-arping-manager.h \
	src/devices/nm-device-ethernet-utils.c \
	src/devices/nm-device-ethernet-utils.h \
	src/devices/nm-device-factory.c \
	src/devices/nm-device-factory.h \
	src/devices/nm-device-generic.c \
	src/devices/nm-device-generic.h \
	src/devices/nm-device-logging.h \
	src/devices/nm-device-private.h \
	\
	src/devices/nm-device-bond.c \
	src/devices/nm-device-bond.h \
	src/devices/nm-device-bridge.c \
	src/devices/nm-device-bridge.h \
	src/devices/nm-device-ethernet.c \
	src/devices/nm-device-ethernet.h \
	src/devices/nm-device-infiniband.c \
	src/devices/nm-device-infiniband.h \
	src/devices/nm-device-ip-tunnel.c \
	src/devices/nm-device-ip-tunnel.h \
	src/devices/nm-device-macvlan.c \
	src/devices/nm-device-macvlan.h \
	src/devices/nm-device-tun.c \
	src/devices/nm-device-tun.h \
	src/devices/nm-device-veth.c \
	src/devices/nm-device-veth.h \
	src/devices/nm-device-vlan.c \
	src/devices/nm-device-vlan.h \
	src/devices/nm-device-vxlan.c \
	src/devices/nm-device-vxlan.h \
	\
	src/dhcp-manager/nm-dhcp-client.c \
	src/dhcp-manager/nm-dhcp-client.h \
	src/dhcp-manager/nm-dhcp-client-logging.h \
	src/dhcp-manager/nm-dhcp-utils.c \
	src/dhcp-manager/nm-dhcp-manager.c \
	src/dhcp-manager/nm-dhcp-manager.h \
	src/dhcp-manager/nm-dhcp-utils.h \
	src/dhcp-manager/nm-dhcp-dhclient.c \
	src/dhcp-manager/nm-dhcp-dhcpcd.c \
	src/dhcp-manager/nm-dhcp-systemd.c \
	src/dhcp-manager/nm-dhcp-helper-api.h \
	src/dhcp-manager/nm-dhcp-listener.c \
	src/dhcp-manager/nm-dhcp-listener.h \
	src/dhcp-manager/nm-dhcp-dhclient-utils.c \
	src/dhcp-manager/nm-dhcp-dhclient-utils.h \
	\
	src/dns-manager/nm-dns-dnsmasq.c \
	src/dns-manager/nm-dns-dnsmasq.h \
	src/dns-manager/nm-dns-systemd-resolved.c \
	src/dns-manager/nm-dns-systemd-resolved.h \
	src/dns-manager/nm-dns-unbound.c \
	src/dns-manager/nm-dns-unbound.h \
	src/dns-manager/nm-dns-manager.c \
	src/dns-manager/nm-dns-manager.h \
	src/dns-manager/nm-dns-plugin.c \
	src/dns-manager/nm-dns-plugin.h \
	\
	src/dnsmasq-manager/nm-dnsmasq-manager.c \
	src/dnsmasq-manager/nm-dnsmasq-manager.h \
	src/dnsmasq-manager/nm-dnsmasq-utils.c \
	src/dnsmasq-manager/nm-dnsmasq-utils.h \
	\
	src/platform/nmp-netns.c \
	src/platform/nmp-netns.h \
	src/platform/nmp-object.c \
	src/platform/nmp-object.h \
	src/platform/nm-platform-utils.c \
	src/platform/nm-platform-utils.h \
	src/platform/nm-platform.c \
	src/platform/nm-platform.h \
	src/platform/nm-linux-platform.c \
	src/platform/nm-linux-platform.h \
	src/platform/wifi/wifi-utils-nl80211.c \
	src/platform/wifi/wifi-utils-nl80211.h \
	src/platform/wifi/wifi-utils-private.h \
	src/platform/wifi/wifi-utils.c \
	src/platform/wifi/wifi-utils.h \
	\
	src/rdisc/nm-lndp-rdisc.c \
	src/rdisc/nm-lndp-rdisc.h \
	src/rdisc/nm-rdisc.c \
	src/rdisc/nm-rdisc.h \
	src/rdisc/nm-rdisc-private.h \
	\
	src/ppp-manager/nm-ppp-manager.c \
	src/ppp-manager/nm-ppp-manager.h \
	src/ppp-manager/nm-ppp-status.h \
	\
	src/settings/nm-agent-manager.c \
	src/settings/nm-agent-manager.h \
	src/settings/nm-inotify-helper.c \
	src/settings/nm-inotify-helper.h \
	src/settings/nm-secret-agent.c \
	src/settings/nm-secret-agent.h \
	src/settings/nm-settings-connection.c \
	src/settings/nm-settings-connection.h \
	src/settings/nm-settings-plugin.c \
	src/settings/nm-settings-plugin.h \
	src/settings/nm-settings.c \
	src/settings/nm-settings.h \
	\
	src/settings/plugins/keyfile/nms-keyfile-connection.c \
	src/settings/plugins/keyfile/nms-keyfile-connection.h \
	src/settings/plugins/keyfile/nms-keyfile-plugin.c \
	src/settings/plugins/keyfile/nms-keyfile-plugin.h \
	src/settings/plugins/keyfile/nms-keyfile-reader.c \
	src/settings/plugins/keyfile/nms-keyfile-reader.h \
	src/settings/plugins/keyfile/nms-keyfile-utils.c \
	src/settings/plugins/keyfile/nms-keyfile-utils.h \
	src/settings/plugins/keyfile/nms-keyfile-writer.c \
	src/settings/plugins/keyfile/nms-keyfile-writer.h \
	\
	src/supplicant-manager/nm-supplicant-config.c \
	src/supplicant-manager/nm-supplicant-config.h \
	src/supplicant-manager/nm-supplicant-interface.c \
	src/supplicant-manager/nm-supplicant-interface.h \
	src/supplicant-manager/nm-supplicant-manager.c \
	src/supplicant-manager/nm-supplicant-manager.h \
	src/supplicant-manager/nm-supplicant-settings-verify.c \
	src/supplicant-manager/nm-supplicant-settings-verify.h \
	src/supplicant-manager/nm-supplicant-types.h \
	\
	src/vpn-manager/nm-vpn-connection.c \
	src/vpn-manager/nm-vpn-connection.h \
	src/vpn-manager/nm-vpn-manager.c \
	src/vpn-manager/nm-vpn-manager.h \
	\
	src/nm-act-request.c \
	src/nm-act-request.h \
	src/nm-active-connection.c \
	src/nm-active-connection.h \
	src/nm-audit-manager.c \
	src/nm-audit-manager.h \
	src/nm-bus-manager.c \
	src/nm-bus-manager.h \
	src/nm-config.c \
	src/nm-config.h \
	src/nm-config-data.c \
	src/nm-config-data.h \
	src/nm-connectivity.c \
	src/nm-connectivity.h \
	src/nm-dcb.c \
	src/nm-dcb.h \
	src/nm-route-manager.c \
	src/nm-route-manager.h \
	src/nm-default-route-manager.c \
	src/nm-default-route-manager.h \
	src/nm-dhcp4-config.c \
	src/nm-dhcp4-config.h \
	src/nm-dhcp6-config.c \
	src/nm-dhcp6-config.h \
	src/nm-dispatcher.c \
	src/nm-dispatcher.h \
	src/nm-src-enum-types.c \
	src/nm-src-enum-types.h \
	src/nm-exported-object.c \
	src/nm-exported-object.h \
	src/nm-firewall-manager.c \
	src/nm-firewall-manager.h \
	src/nm-proxy-config.c \
	src/nm-proxy-config.h \
	src/nm-ip4-config.c \
	src/nm-ip4-config.h \
	src/nm-ip6-config.c \
	src/nm-ip6-config.h \
	src/nm-auth-manager.c \
	src/nm-auth-manager.h \
	src/nm-auth-subject.c \
	src/nm-auth-subject.h \
	src/nm-auth-utils.c \
	src/nm-auth-utils.h \
	src/nm-manager.c \
	src/nm-manager.h \
	src/nm-multi-index.c \
	src/nm-multi-index.h \
	src/nm-pacrunner-manager.c \
	src/nm-pacrunner-manager.h \
	src/nm-policy.c \
	src/nm-policy.h \
	src/nm-rfkill-manager.c \
	src/nm-rfkill-manager.h \
	src/nm-session-monitor.h \
	src/nm-session-monitor.c \
	src/nm-sleep-monitor.c \
	src/nm-sleep-monitor.h \
	src/nm-types.h \
	src/NetworkManagerUtils.c \
	src/NetworkManagerUtils.h \
	$(NULL)

if WITH_WEXT
src_libNetworkManager_la_SOURCES += \
	src/platform/wifi/wifi-utils-wext.c \
	src/platform/wifi/wifi-utils-wext.h
endif


src_libNetworkManager_la_LIBADD = \
	libnm-core/libnm-core.la \
	introspection/libnmdbus.la \
	src/libNetworkManagerBase.la \
	src/libsystemd-nm.la \
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
src_libNetworkManager_la_LIBADD += $(LIBSOUP_LIBS)
endif

###############################################################################

src_libNetworkManagerTest_la_CPPFLAGS = $(src_cppflags)

src_libNetworkManagerTest_la_SOURCES = \
	src/rdisc/nm-fake-rdisc.c \
	src/rdisc/nm-fake-rdisc.h \
	src/platform/nm-fake-platform.c \
	src/platform/nm-fake-platform.h

src_libNetworkManagerTest_la_LIBADD = \
	src/libNetworkManager.la

###############################################################################

EXTRA_src_NetworkManager_DEPENDENCIES = \
	src/NetworkManager.ver

src_NetworkManager_CPPFLAGS = $(src_cppflags)

src_NetworkManager_SOURCES = \
	src/main-utils.c \
	src/main-utils.h \
	src/main.c

src_NetworkManager_LDADD = \
	src/libNetworkManager.la

src_NetworkManager_LDFLAGS = \
	-rdynamic \
	-Wl,--version-script="$(srcdir)/src/NetworkManager.ver"

###############################################################################

src_nm_iface_helper_CPPFLAGS = \
	$(src_cppflags) \
	-DNM_DHCP_INTERNAL_ONLY

src_nm_iface_helper_SOURCES = \
	\
	src/dhcp-manager/nm-dhcp-client.c \
	src/dhcp-manager/nm-dhcp-client.h \
	src/dhcp-manager/nm-dhcp-client-logging.h \
	src/dhcp-manager/nm-dhcp-utils.c \
	src/dhcp-manager/nm-dhcp-utils.h \
	src/dhcp-manager/nm-dhcp-manager.c \
	src/dhcp-manager/nm-dhcp-manager.h \
	src/dhcp-manager/nm-dhcp-systemd.c \
	\
	src/platform/nmp-netns.c \
	src/platform/nmp-netns.h \
	src/platform/nmp-object.c \
	src/platform/nmp-object.h \
	src/platform/nm-platform-utils.c \
	src/platform/nm-platform-utils.h \
	src/platform/nm-platform.c \
	src/platform/nm-platform.h \
	src/platform/nm-linux-platform.c \
	src/platform/nm-linux-platform.h \
	src/platform/wifi/wifi-utils-nl80211.c \
	src/platform/wifi/wifi-utils-nl80211.h \
	src/platform/wifi/wifi-utils-private.h \
	src/platform/wifi/wifi-utils.c \
	src/platform/wifi/wifi-utils.h \
	\
	src/nm-pacrunner-manager.c \
	src/nm-pacrunner-manager.h \
	\
	src/rdisc/nm-lndp-rdisc.c \
	src/rdisc/nm-lndp-rdisc.h \
	src/rdisc/nm-rdisc.c \
	src/rdisc/nm-rdisc.h \
	\
	src/nm-route-manager.c \
	src/nm-route-manager.h \
	\
	src/nm-exported-object.c \
	src/nm-exported-object.h \
	src/nm-proxy-config.c \
	src/nm-proxy-config.h \
	src/nm-ip4-config.c \
	src/nm-ip4-config.h \
	src/nm-ip6-config.c \
	src/nm-ip6-config.h \
	\
	src/nm-src-enum-types.c \
	src/nm-src-enum-types.h \
	src/nm-multi-index.c \
	src/nm-multi-index.h \
	src/NetworkManagerUtils.c \
	src/NetworkManagerUtils.h \
	\
	src/nm-iface-helper.c \
	src/main-utils.c \
	src/main-utils.h

if WITH_WEXT
src_nm_iface_helper_SOURCES += \
	src/platform/wifi/wifi-utils-wext.c \
	src/platform/wifi/wifi-utils-wext.h
endif

src_nm_iface_helper_LDADD = \
	libnm-core/libnm-core.la \
	introspection/libnmdbus.la \
	src/libNetworkManagerBase.la \
	src/libsystemd-nm.la \
	$(GLIB_LIBS) \
	$(GUDEV_LIBS) \
	$(LIBNL_LIBS) \
	$(LIBNDP_LIBS) \
	$(DL_LIBS) \
	$(LIBM)

src_nm_iface_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"

###############################################################################

GLIB_GENERATED += \
	src/nm-src-enum-types.h \
	src/nm-src-enum-types.c
nm_src_enum_types_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include <nm-core-enum-types.h>\n'
nm_src_enum_types_MKENUMS_C_FLAGS = --identifier-prefix NM --fhead '\#include "nm-default.h"\n'
nm_src_enum_types_sources = $(filter-out \
                              %/nm-device-private.h \
                              %/nm-rdisc-private.h \
                              %/wifi-utils-private.h \
                              %/nm-dhcp-client-logging.h \
                              %/nm-device-logging.h \
                              , $(src_libNetworkManager_la_SOURCES))

###############################################################################

EXTRA_DIST += \
	src/org.freedesktop.NetworkManager.conf \
	src/nm-test-utils-core.h \
	src/NetworkManager.ver

###############################################################################
# src/dhcp-manager
###############################################################################

libexec_PROGRAMS += src/dhcp-manager/nm-dhcp-helper

src_dhcp_manager_nm_dhcp_helper_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I${top_builddir}/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""nm-dhcp-helper"\" \
	-DNMRUNDIR=\"$(nmrundir)\"

src_dhcp_manager_nm_dhcp_helper_SOURCES = \
	src/dhcp-manager/nm-dhcp-helper.c \
	src/dhcp-manager/nm-dhcp-helper-api.h \
	$(NULL)

src_dhcp_manager_nm_dhcp_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"

src_dhcp_manager_nm_dhcp_helper_LDADD = $(GLIB_LIBS)

###############################################################################
# src/dhcp-manager/tests
###############################################################################

src_dhcp_manager_tests_cppflags = \
	-I$(top_srcdir)/shared \
	-I${top_builddir}/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DTESTDIR="\"$(abs_srcdir)/src/dhcp-manager/tests\""

src_dhcp_manager_tests_ldadd = \
	src/libNetworkManager.la

src_dhcp_manager_tests_programs = \
	src/dhcp-manager/tests/test-dhcp-dhclient \
	src/dhcp-manager/tests/test-dhcp-utils

check_programs += $(src_dhcp_manager_tests_programs)

src_dhcp_manager_tests_test_dhcp_dhclient_CPPFLAGS = $(src_dhcp_manager_tests_cppflags)
src_dhcp_manager_tests_test_dhcp_utils_CPPFLAGS = $(src_dhcp_manager_tests_cppflags)

src_dhcp_manager_tests_test_dhcp_dhclient_LDADD = $(src_dhcp_manager_tests_ldadd)
src_dhcp_manager_tests_test_dhcp_utils_LDADD = $(src_dhcp_manager_tests_ldadd)

EXTRA_DIST += \
	src/dhcp-manager/tests/test-dhclient-duid.leases \
	src/dhcp-manager/tests/test-dhclient-commented-duid.leases \
	src/dhcp-manager/tests/leases/basic.leases \
	src/dhcp-manager/tests/leases/malformed1.leases \
	src/dhcp-manager/tests/leases/malformed2.leases \
	src/dhcp-manager/tests/leases/malformed3.leases

###############################################################################
# src/ppp-manager
###############################################################################

if WITH_PPP

pppd_plugin_LTLIBRARIES += src/ppp-manager/nm-pppd-plugin.la

src_ppp_manager_nm_pppd_plugin_la_CPPFLAGS = \
	-I${top_srcdir}/shared \
	-I${top_builddir}/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_srcdir}/src \
	-I${top_builddir}/libnm-core \
	-DG_LOG_DOMAIN=\""nm-pppd-plugin"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS)

src_ppp_manager_nm_pppd_plugin_la_SOURCES = \
	src/ppp-manager/nm-pppd-plugin.c \
	src/ppp-manager/nm-pppd-plugin.h \
	src/ppp-manager/nm-ppp-status.h

src_ppp_manager_nm_pppd_plugin_la_LDFLAGS = \
	-module -avoid-version

src_ppp_manager_nm_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(DL_LIBS)

endif

###############################################################################
# src/settings/plugins/keyfile/tests
###############################################################################

check_programs += src/settings/plugins/keyfile/tests/test-keyfile

src_settings_plugins_keyfile_tests_test_keyfile_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/settings/plugins/keyfile \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DTEST_KEYFILES_DIR=\"$(abs_srcdir)/src/settings/plugins/keyfile/tests/keyfiles\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/src/settings/plugins/keyfile/tests/keyfiles\" \
	-DNMCONFDIR=\"nonexistent\"

src_settings_plugins_keyfile_tests_test_keyfile_LDFLAGS = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

src_settings_plugins_keyfile_tests_test_keyfile_LDADD = \
	src/libNetworkManager.la

EXTRA_DIST += \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_Connection \
	src/settings/plugins/keyfile/tests/keyfiles/Test_GSM_Connection \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wireless_Connection \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_Connection_MAC_Case \
	src/settings/plugins/keyfile/tests/keyfiles/Test_MAC_Old_Format \
	src/settings/plugins/keyfile/tests/keyfiles/Test_MAC_IB_Old_Format \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_Connection_IP6 \
	src/settings/plugins/keyfile/tests/keyfiles/ATT_Data_Connect_BT \
	src/settings/plugins/keyfile/tests/keyfiles/ATT_Data_Connect_Plain \
	src/settings/plugins/keyfile/tests/keyfiles/Test_String_SSID \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Intlist_SSID \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Intlike_SSID \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Intlike_SSID_2 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_Old \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_New \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_Blob \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_Path_Missing \
	src/settings/plugins/keyfile/tests/keyfiles/Test_InfiniBand_Connection \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Bridge_Main \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Bridge_Component \
	src/settings/plugins/keyfile/tests/keyfiles/Test_New_Wired_Group_Name \
	src/settings/plugins/keyfile/tests/keyfiles/Test_New_Wireless_Group_Names \
	src/settings/plugins/keyfile/tests/keyfiles/Test_minimal_1 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_minimal_2 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_1 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_2 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_3 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_4 \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Missing_Vlan_Setting \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Missing_Vlan_Flags \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Missing_ID_UUID \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Enum_Property \
	src/settings/plugins/keyfile/tests/keyfiles/Test_Flags_Property \
	\
	src/settings/plugins/keyfile/tests/keyfiles/test-ca-cert.pem \
	src/settings/plugins/keyfile/tests/keyfiles/test-key-and-cert.pem

###############################################################################
# src/settings/plugins/ibft
###############################################################################

if CONFIG_PLUGIN_IBFT

pkglib_LTLIBRARIES += src/settings/plugins/ibft/libnm-settings-plugin-ibft.la

noinst_LTLIBRARIES += src/settings/plugins/ibft/libnms-ibft-core.la

src_settings_plugins_ibft_cppflags = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

src_settings_plugins_ibft_libnms_ibft_core_la_CPPFLAGS = $(src_settings_plugins_ibft_cppflags)

src_settings_plugins_ibft_libnms_ibft_core_la_SOURCES = \
	src/settings/plugins/ibft/nms-ibft-reader.c \
	src/settings/plugins/ibft/nms-ibft-reader.h

src_settings_plugins_ibft_libnm_settings_plugin_ibft_la_SOURCES = \
	src/settings/plugins/ibft/nms-ibft-plugin.c \
	src/settings/plugins/ibft/nms-ibft-plugin.h \
	src/settings/plugins/ibft/nms-ibft-connection.c \
	src/settings/plugins/ibft/nms-ibft-connection.h

src_settings_plugins_ibft_libnm_settings_plugin_ibft_la_CPPFLAGS = $(src_settings_plugins_ibft_cppflags)

src_settings_plugins_ibft_libnm_settings_plugin_ibft_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-settings.ver"

src_settings_plugins_ibft_libnm_settings_plugin_ibft_la_LIBADD = \
	src/settings/plugins/ibft/libnms-ibft-core.la

check_programs += src/settings/plugins/ibft/tests/test-ibft

src_settings_plugins_ibft_tests_test_ibft_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/src/settings/plugins/ibft \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DTEST_IBFT_DIR=\"$(abs_srcdir)/src/settings/plugins/ibft/tests\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/src/settings/plugins/ibft/tests\"

src_settings_plugins_ibft_tests_test_ibft_LDFLAGS = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

src_settings_plugins_ibft_tests_test_ibft_LDADD = \
	src/settings/plugins/ibft/libnms-ibft-core.la \
	src/libNetworkManager.la

EXTRA_DIST += \
	src/settings/plugins/ibft/tests/iscsiadm-test-dhcp \
	src/settings/plugins/ibft/tests/iscsiadm-test-static \
	src/settings/plugins/ibft/tests/iscsiadm-test-bad-ipaddr \
	src/settings/plugins/ibft/tests/iscsiadm-test-bad-gateway \
	src/settings/plugins/ibft/tests/iscsiadm-test-bad-dns1 \
	src/settings/plugins/ibft/tests/iscsiadm-test-bad-dns2 \
	src/settings/plugins/ibft/tests/iscsiadm-test-bad-entry \
	src/settings/plugins/ibft/tests/iscsiadm-test-bad-record \
	src/settings/plugins/ibft/tests/iscsiadm-test-vlan

check-local-symbols-settings-ibft: src/settings/plugins/ibft/libnm-settings-plugin-ibft.la
	$(call check_so_symbols,$(builddir)/src/settings/plugins/ibft/.libs/libnm-settings-plugin-ibft.so)

check_local += check-local-symbols-settings-ibft

endif

###############################################################################
# src/settings/plugins/ifcfg-rh
###############################################################################

if CONFIG_PLUGIN_IFCFG_RH

pkglib_LTLIBRARIES += src/settings/plugins/ifcfg-rh/libnm-settings-plugin-ifcfg-rh.la

noinst_LTLIBRARIES += \
	src/settings/plugins/ifcfg-rh/libnmdbus-ifcfg-rh.la \
	src/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la

src_settings_plugins_ifcfg_rh_cppflags = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/settings/plugins/ifcfg-rh \
	-I$(top_builddir)/src/settings/plugins/ifcfg-rh \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	$(NSS_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

###############################################################################

nodist_src_settings_plugins_ifcfg_rh_libnmdbus_ifcfg_rh_la_SOURCES = \
	src/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.c \
	src/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h

src_settings_plugins_ifcfg_rh_libnmdbus_ifcfg_rh_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(src_settings_plugins_ifcfg_rh_cppflags))

BUILT_SOURCES += $(nodist_src_settings_plugins_ifcfg_rh_libnmdbus_ifcfg_rh_la_SOURCES)

src/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h: src/settings/plugins/ifcfg-rh/nm-ifcfg-rh.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix com.redhat \
		$<

src/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.c: src/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h
	@true

###############################################################################

src_settings_plugins_ifcfg_rh_libnms_ifcfg_rh_core_la_SOURCES = \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-common.h \
	src/settings/plugins/ifcfg-rh/shvar.c \
	src/settings/plugins/ifcfg-rh/shvar.h \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-utils.c \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-utils.h \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-reader.c \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-reader.h \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-writer.c \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-writer.h

src_settings_plugins_ifcfg_rh_libnms_ifcfg_rh_core_la_CPPFLAGS = $(src_settings_plugins_ifcfg_rh_cppflags)

###############################################################################

src_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_SOURCES = \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-connection.c \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-connection.h \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-plugin.c \
	src/settings/plugins/ifcfg-rh/nms-ifcfg-rh-plugin.h

src_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_CPPFLAGS = $(src_settings_plugins_ifcfg_rh_cppflags)

src_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(top_srcdir)/linker-script-settings.ver"

src_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_LIBADD = \
	src/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la \
	src/settings/plugins/ifcfg-rh/libnmdbus-ifcfg-rh.la

check-local-symbols-settings-ifcfg-rh: src/settings/plugins/ifcfg-rh/libnm-settings-plugin-ifcfg-rh.la
	$(call check_so_symbols,$(builddir)/src/settings/plugins/ifcfg-rh/.libs/libnm-settings-plugin-ifcfg-rh.so)

check_local += check-local-symbols-settings-ifcfg-rh

###############################################################################
# src/settings/plugins/ifcfg-rh/tests
###############################################################################

check_programs += src/settings/plugins/ifcfg-rh/tests/test-ifcfg-rh

src_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_SOURCES = \
	src/settings/plugins/ifcfg-rh/tests/test-ifcfg-rh.c

src_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/settings/plugins/ifcfg-rh \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DTEST_IFCFG_DIR=\"$(abs_srcdir)/src/settings/plugins/ifcfg-rh/tests\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/src/settings/plugins/ifcfg-rh/tests\" \
	-DSYSCONFDIR=\"nonexistent\" \
	-DSBINDIR=\"nonexistent\"

src_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_LDFLAGS = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

src_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_LDADD = \
	src/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la \
	src/libNetworkManager.la

endif

EXTRA_DIST += \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-minimal \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-misc-variables \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-variables-corner-cases-1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-nm-controlled \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-nm-controlled-unrecognized \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-unrecognized \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-bootproto \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp-plus-ip \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-shared-plus-ip \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp-send-hostname \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp6-only \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-autoip \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-global-gateway \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-global-gateway \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-global-gateway-ignore \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-global-gateway-ignore \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-obsolete-gateway-n \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-never-default \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-never-default \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-defroute-no \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-defroute-no-gatewaydev-yes \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-defroute-no-gatewaydev-yes \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-peap-mschapv2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wired-8021x-peap-mschapv2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-tls-agent \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-tls-always \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-802-1X-subj-matches \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-802-1x-ttls-eapgtc \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-onboot-no \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-noip \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-auto \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-quoted \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-long-quoted \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-hex \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-long-hex \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-bad-hex \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-adhoc \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-adhoc \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-eap-ttls-chap \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-eap-ttls-chap \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-leap \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-leap \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-leap-agent \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-leap-always-ask \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-unquoted \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-unquoted2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-adhoc \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-adhoc \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-hex \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-hex \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-tls \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-eap-tls \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-ttls-tls \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-eap-ttls-tls \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-hidden \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-band-a \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-band-a-channel-mismatch \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-band-bg-channel-mismatch \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-always \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-never \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-default \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-missing \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/test_ca_cert.pem \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/test1_key_and_cert.pem \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-ibft \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-static-routes-legacy \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/route-test-static-routes-legacy \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-sit-ignore \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-routes \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/route-test-wired-static-routes \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-routes-legacy \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/route-test-wired-static-routes-legacy \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-3 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-4 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv6-manual \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/route6-test-wired-ipv6-manual \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-no-prefix-8 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-no-prefix-16 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-no-prefix-24 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv6-only \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-passphrase \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-passphrase \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-40-ascii \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-40-ascii \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-104-ascii \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-104-ascii \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-qeth-static \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ctc-static \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bridge-main \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bridge-component \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bridge-missing-stp \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-interface \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-only-vlanid \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-only-device \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-physdev \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-reorder-hdr-1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-reorder-hdr-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-flags-1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-flags-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-no-keys \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-permissions \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-agent-keys \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-dynamic-wep-leap \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-dynamic-wep-leap \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-infiniband \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-main \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-slave \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-slave-ib \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-mode-numeric \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-default-app-priorities \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-bad-booleans \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-short-booleans \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-bad-uints \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-short-uints \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-bad-percent \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-short-percent \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-pgpct-not-100 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-fcoe-fabric \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-fcoe-vn2vn \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-master-1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-master-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-master-invalid \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-port-1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-port-2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-port-empty-config \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-trailing-spaces \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dns-options \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-wake-on-lan \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv6-only-1

# make target dependencies can't have colons in their names, which ends up
# meaning that we can't add the alias files to EXTRA_DIST. They are instead
# dist'ed via dist-hook-settings-ifcfg-rh below.
src_settings_plugins_ifcfg_rh_tests_network_scripts_alias_files = \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0:1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0:2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0:99 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem1:1 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem2 \
	src/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem2:1

dist-hook-settings-ifcfg-rh-alias-files:
	@for f in $(src_settings_plugins_ifcfg_rh_tests_network_scripts_alias_files); do \
		cp $(abs_srcdir)/$$f $(distdir)/src/settings/plugins/ifcfg-rh/tests/network-scripts/; \
	done

dist_hook += dist-hook-settings-ifcfg-rh-alias-files

###############################################################################

dbusservice_DATA += src/settings/plugins/ifcfg-rh/nm-ifcfg-rh.conf

EXTRA_DIST += \
	src/settings/plugins/ifcfg-rh/nm-ifcfg-rh.conf \
	src/settings/plugins/ifcfg-rh/nm-ifcfg-rh.xml

###############################################################################
# src/settings/plugins/ifupdown
###############################################################################

if CONFIG_PLUGIN_IFUPDOWN

pkglib_LTLIBRARIES += src/settings/plugins/ifupdown/libnm-settings-plugin-ifupdown.la

noinst_LTLIBRARIES += src/settings/plugins/ifupdown/libnms-ifupdown-core.la

src_settings_plugins_ifupdown_cppflags = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"


src_settings_plugins_ifupdown_libnms_ifupdown_core_la_SOURCES = \
	src/settings/plugins/ifupdown/nms-ifupdown-interface-parser.c \
	src/settings/plugins/ifupdown/nms-ifupdown-interface-parser.h \
	src/settings/plugins/ifupdown/nms-ifupdown-parser.c \
	src/settings/plugins/ifupdown/nms-ifupdown-parser.h

src_settings_plugins_ifupdown_libnms_ifupdown_core_la_CPPFLAGS = $(src_settings_plugins_ifupdown_cppflags)


src_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_SOURCES = \
	src/settings/plugins/ifupdown/nms-ifupdown-connection.c \
	src/settings/plugins/ifupdown/nms-ifupdown-connection.h \
	src/settings/plugins/ifupdown/nms-ifupdown-plugin.c \
	src/settings/plugins/ifupdown/nms-ifupdown-plugin.h

src_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_CPPFLAGS = $(src_settings_plugins_ifupdown_cppflags)

src_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(top_srcdir)/linker-script-settings.ver"

src_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_LIBADD = \
	src/settings/plugins/ifupdown/libnms-ifupdown-core.la

check-local-symbols-settings-ifupdown: src/settings/plugins/ifupdown/libnm-settings-plugin-ifupdown.la
	$(call check_so_symbols,$(builddir)/src/settings/plugins/ifupdown/.libs/libnm-settings-plugin-ifupdown.so)

check_local += check-local-symbols-settings-ifupdown

endif

###############################################################################

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA += src/org.freedesktop.NetworkManager.conf

###############################################################################

if ENABLE_TESTS
noinst_PROGRAMS += $(check_programs)
noinst_LTLIBRARIES += $(check_ltlibraries)
else
check_PROGRAMS += $(check_programs)
check_LTLIBRARIES += $(check_ltlibraries)
endif

TESTS += $(check_programs)

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
	tools/check-exports.sh \
	tools/create-exports-NetworkManager.sh \
	tools/debug-helper.py \
	tools/run-nm-test.sh \
	tools/test-networkmanager-service.py \
	tools/test-sudo-wrapper.sh \
	tools/enums-to-docbook.pl \
	\
	$(NULL)

BUILT_SOURCES += \
	$(GLIB_GENERATED) \
	$(gir_DATA) \
	$(typelib_DATA)

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

check-local: $(check_local)

dist-hook: $(dist_hook)

###############################################################################

install-data-hook:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(rundir)
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(statedir)
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(pkglibdir)

###############################################################################

cscope:
	cscope -b -q -R -sshared -ssrc -slibnm-core -slibnm -slibnm-glib -slibnm-util -sclients;

###############################################################################

.PHONY: cscope $(check_local) $(dist_hook)
