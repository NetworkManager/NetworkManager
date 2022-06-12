# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_client_public_inc = include_directories('.')

libnm_client_headers = files(
  'NetworkManager.h',
  'nm-access-point.h',
  'nm-active-connection.h',
  'nm-autoptr.h',
  'nm-checkpoint.h',
  'nm-client.h',
  'nm-conn-utils.h',
  'nm-device-6lowpan.h',
  'nm-device-adsl.h',
  'nm-device-bond.h',
  'nm-device-bridge.h',
  'nm-device-bt.h',
  'nm-device-dummy.h',
  'nm-device-ethernet.h',
  'nm-device-generic.h',
  'nm-device-infiniband.h',
  'nm-device-ip-tunnel.h',
  'nm-device-loopback.h',
  'nm-device-macsec.h',
  'nm-device-macvlan.h',
  'nm-device-modem.h',
  'nm-device-olpc-mesh.h',
  'nm-device-ovs-bridge.h',
  'nm-device-ovs-interface.h',
  'nm-device-ovs-port.h',
  'nm-device-ppp.h',
  'nm-device-team.h',
  'nm-device-tun.h',
  'nm-device-veth.h',
  'nm-device-vlan.h',
  'nm-device-vrf.h',
  'nm-device-vxlan.h',
  'nm-device-wifi-p2p.h',
  'nm-device-wifi.h',
  'nm-device-wimax.h',
  'nm-device-wireguard.h',
  'nm-device-wpan.h',
  'nm-device.h',
  'nm-dhcp-config.h',
  'nm-ethtool-utils.h',
  'nm-ip-config.h',
  'nm-object.h',
  'nm-remote-connection.h',
  'nm-secret-agent-old.h',
  'nm-vpn-connection.h',
  'nm-vpn-editor.h',
  'nm-vpn-plugin-old.h',
  'nm-vpn-service-plugin.h',
  'nm-wifi-p2p-peer.h',
  'nm-wimax-nsp.h',
)

libnm_client_public_enum_sources = gnome.mkenums(
  'nm-enum-types',
  sources: libnm_client_headers,
  identifier_prefix: nm_id_prefix,
  c_template: 'nm-enum-types.c.template',
  h_template: 'nm-enum-types.h.template',
  install_header: true,
  install_dir: libnm_pkgincludedir,
)

install_headers(
  libnm_core_headers + libnm_client_headers + [nm_version_macro_header],
  subdir: libnm_name,
)

libnm_client_public_dep = declare_dependency(
  sources: libnm_client_public_enum_sources[1],
  include_directories: [
    libnm_client_public_inc,
    src_inc,
    top_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
    glib_dep,
  ],
)
