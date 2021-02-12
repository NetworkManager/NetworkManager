# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_core_public_inc = include_directories('.')

libnm_core_headers = files(
  'nm-connection.h',
  'nm-core-types.h',
  'nm-dbus-interface.h',
  'nm-errors.h',
  'nm-keyfile.h',
  'nm-setting-6lowpan.h',
  'nm-setting-8021x.h',
  'nm-setting-adsl.h',
  'nm-setting-bluetooth.h',
  'nm-setting-bond.h',
  'nm-setting-bridge-port.h',
  'nm-setting-bridge.h',
  'nm-setting-cdma.h',
  'nm-setting-connection.h',
  'nm-setting-dcb.h',
  'nm-setting-dummy.h',
  'nm-setting-ethtool.h',
  'nm-setting-generic.h',
  'nm-setting-gsm.h',
  'nm-setting-hostname.h',
  'nm-setting-infiniband.h',
  'nm-setting-ip-config.h',
  'nm-setting-ip-tunnel.h',
  'nm-setting-ip4-config.h',
  'nm-setting-ip6-config.h',
  'nm-setting-macsec.h',
  'nm-setting-macvlan.h',
  'nm-setting-match.h',
  'nm-setting-olpc-mesh.h',
  'nm-setting-ovs-bridge.h',
  'nm-setting-ovs-dpdk.h',
  'nm-setting-ovs-external-ids.h',
  'nm-setting-ovs-interface.h',
  'nm-setting-ovs-patch.h',
  'nm-setting-ovs-port.h',
  'nm-setting-ppp.h',
  'nm-setting-pppoe.h',
  'nm-setting-proxy.h',
  'nm-setting-serial.h',
  'nm-setting-sriov.h',
  'nm-setting-tc-config.h',
  'nm-setting-team-port.h',
  'nm-setting-team.h',
  'nm-setting-tun.h',
  'nm-setting-user.h',
  'nm-setting-veth.h',
  'nm-setting-vlan.h',
  'nm-setting-vpn.h',
  'nm-setting-vrf.h',
  'nm-setting-vxlan.h',
  'nm-setting-wifi-p2p.h',
  'nm-setting-wimax.h',
  'nm-setting-wired.h',
  'nm-setting-wireguard.h',
  'nm-setting-wireless-security.h',
  'nm-setting-wireless.h',
  'nm-setting-wpan.h',
  'nm-setting.h',
  'nm-simple-connection.h',
  'nm-utils.h',
  'nm-version.h',
  'nm-vpn-dbus-interface.h',
  'nm-vpn-editor-plugin.h',
  'nm-vpn-plugin-info.h',
)

nm_version_macro_header = configure_file(
  input: 'nm-version-macros.h.in',
  output: '@BASENAME@',
  configuration: data_conf,
)

libnm_core_public_enum_sources = gnome.mkenums_simple(
  'nm-core-enum-types',
  sources: libnm_core_headers + [nm_version_macro_header],
  identifier_prefix: nm_id_prefix,
  body_prefix: '#include "libnm-core-impl/nm-default-libnm-core.h"',
  install_header: true,
  install_dir: libnm_pkgincludedir,
)

libnm_core_public_dep = declare_dependency(
  sources: libnm_core_headers + [
    libnm_core_public_enum_sources[1],
    nm_version_macro_header,
  ],
  include_directories: [
    libnm_core_public_inc,
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
  ],
)

docbooks = [
  ['nm-dbus-types',     'nm-dbus-interface.h',     'NetworkManager D-Bus API Types'],
  ['nm-vpn-dbus-types', 'nm-vpn-dbus-interface.h', 'VPN Plugin D-Bus API Types'],
]

foreach docbook: docbooks
  output = docbook[0] + '.xml'

  xml = custom_target(
    output,
    input: docbook[1],
    output: output,
    capture: true,
    command: [
      perl,
      join_paths(source_root, 'tools', 'enums-to-docbook.pl'),
      docbook[0],
      docbook[2],
      '@INPUT@',
    ],
    # FIXME: gtkdoc does not depend directly on this.
    #        https://github.com/mesonbuild/meson/pull/2806
    build_by_default: true,
  )

  content_files += xml.full_path()
endforeach
