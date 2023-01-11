# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_core_impl_inc = include_directories('.')

libnm_core_settings_sources = files(
  'nm-setting-6lowpan.c',
  'nm-setting-8021x.c',
  'nm-setting-adsl.c',
  'nm-setting-bluetooth.c',
  'nm-setting-bond.c',
  'nm-setting-bond-port.c',
  'nm-setting-bridge-port.c',
  'nm-setting-bridge.c',
  'nm-setting-cdma.c',
  'nm-setting-connection.c',
  'nm-setting-dcb.c',
  'nm-setting-dummy.c',
  'nm-setting-ethtool.c',
  'nm-setting-generic.c',
  'nm-setting-gsm.c',
  'nm-setting-hostname.c',
  'nm-setting-infiniband.c',
  'nm-setting-ip-config.c',
  'nm-setting-ip-tunnel.c',
  'nm-setting-ip4-config.c',
  'nm-setting-ip6-config.c',
  'nm-setting-loopback.c',
  'nm-setting-macsec.c',
  'nm-setting-macvlan.c',
  'nm-setting-match.c',
  'nm-setting-olpc-mesh.c',
  'nm-setting-ovs-bridge.c',
  'nm-setting-ovs-dpdk.c',
  'nm-setting-ovs-external-ids.c',
  'nm-setting-ovs-interface.c',
  'nm-setting-ovs-other-config.c',
  'nm-setting-ovs-patch.c',
  'nm-setting-ovs-port.c',
  'nm-setting-ppp.c',
  'nm-setting-pppoe.c',
  'nm-setting-proxy.c',
  'nm-setting-serial.c',
  'nm-setting-sriov.c',
  'nm-setting-tc-config.c',
  'nm-setting-team-port.c',
  'nm-setting-team.c',
  'nm-setting-tun.c',
  'nm-setting-user.c',
  'nm-setting-veth.c',
  'nm-setting-vlan.c',
  'nm-setting-vpn.c',
  'nm-setting-vrf.c',
  'nm-setting-vxlan.c',
  'nm-setting-wifi-p2p.c',
  'nm-setting-wimax.c',
  'nm-setting-wired.c',
  'nm-setting-wireguard.c',
  'nm-setting-wireless-security.c',
  'nm-setting-wireless.c',
  'nm-setting-wpan.c',
)

libnm_core_impl_sources = files(
  'nm-connection.c',
  'nm-errors.c',
  'nm-keyfile-utils.c',
  'nm-keyfile.c',
  'nm-meta-setting-base-impl.c',
  'nm-property-compare.c',
  'nm-setting.c',
  'nm-simple-connection.c',
  'nm-team-utils.c',
  'nm-utils.c',
  'nm-vpn-editor-plugin.c',
  'nm-vpn-plugin-info.c',
)

libnm_core_impl = static_library(
  'nm-core-impl',
  sources: libnm_core_impl_sources + libnm_core_settings_sources + libnm_core_public_enum_sources + [nm_version_macro_header],
  include_directories: [
    top_inc,
    src_inc,
    libnm_core_intern_inc,
  ],
  dependencies: [
    dl_dep,
    libnm_core_public_dep,
    uuid_dep,
  ],
)

###############################################################################

gen_metadata_nm_settings_libnm_core = executable(
  'gen-metadata-nm-settings-libnm-core',
  files(
    'gen-metadata-nm-settings-libnm-core.c',
  ),
  dependencies: [
    libnm_core_public_dep,
  ],
  link_with: [
    libnm_core_aux_intern,
    libnm_core_impl,
    libnm_crypto,
    libnm_base,
    libnm_systemd_shared,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
)

if enable_docs
  gen_metadata_nm_settings_libnm_core_xml = custom_target(
    'gen-metadata-nm-settings-libnm-core.xml',
    output: 'gen-metadata-nm-settings-libnm-core.xml',
    command: [ gen_metadata_nm_settings_libnm_core ],
    capture: true,
  )

  test(
    'check-local-gen-metadata-nm-settings-libnm-core',
    find_program(join_paths(source_root, 'tools', 'check-compare-generated.sh')),
    args: [
      source_root + '/src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml.in',
      gen_metadata_nm_settings_libnm_core_xml,
    ],
  )
else
  gen_metadata_nm_settings_libnm_core_xml = configure_file(
    input: 'gen-metadata-nm-settings-libnm-core.xml.in',
    output: '@BASENAME@',
    configuration: configuration_data(),
  )
endif
