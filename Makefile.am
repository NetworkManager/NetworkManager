include $(GLIB_MAKEFILE)
-include $(INTROSPECTION_MAKEFILE)
include nm.mk

@GNOME_CODE_COVERAGE_RULES@

@NM_LOG_COMPILER@

###############################################################################

AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES =
noinst_PROGRAMS =
noinst_DATA =
lib_LTLIBRARIES =
CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =
TESTS =
BUILT_SOURCES =
GLIB_GENERATED =
check_local =

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

SUBDIRS = \
	. \
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

if ENABLE_TESTS

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

noinst_PROGRAMS += $(libnm_core_tests_programs)

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

TESTS += $(libnm_core_tests_programs)

endif

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

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

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

###############################################################################

cscope:
	cscope -b -q -R -sshared -ssrc -slibnm-core -slibnm -slibnm-glib -slibnm-util -sclients;

###############################################################################

.PHONY: cscope $(check_local)
