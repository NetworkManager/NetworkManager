# SPDX-License-Identifier: LGPL-2.1-or-later

ifaces = [
  'org.freedesktop.NetworkManager',
  'org.freedesktop.NetworkManager.AccessPoint',
  'org.freedesktop.NetworkManager.AgentManager',
  'org.freedesktop.NetworkManager.Checkpoint',
  'org.freedesktop.NetworkManager.Connection.Active',
  'org.freedesktop.NetworkManager.DHCP4Config',
  'org.freedesktop.NetworkManager.DHCP6Config',
  'org.freedesktop.NetworkManager.Device',
  'org.freedesktop.NetworkManager.Device.Adsl',
  'org.freedesktop.NetworkManager.Device.Bluetooth',
  'org.freedesktop.NetworkManager.Device.Bond',
  'org.freedesktop.NetworkManager.Device.Bridge',
  'org.freedesktop.NetworkManager.Device.Dummy',
  'org.freedesktop.NetworkManager.Device.Generic',
  'org.freedesktop.NetworkManager.Device.Hsr',
  'org.freedesktop.NetworkManager.Device.IPTunnel',
  'org.freedesktop.NetworkManager.Device.Infiniband',
  'org.freedesktop.NetworkManager.Device.Ipvlan',
  'org.freedesktop.NetworkManager.Device.Loopback',
  'org.freedesktop.NetworkManager.Device.Lowpan',
  'org.freedesktop.NetworkManager.Device.Macsec',
  'org.freedesktop.NetworkManager.Device.Macvlan',
  'org.freedesktop.NetworkManager.Device.Modem',
  'org.freedesktop.NetworkManager.Device.OlpcMesh',
  'org.freedesktop.NetworkManager.Device.OvsBridge',
  'org.freedesktop.NetworkManager.Device.OvsInterface',
  'org.freedesktop.NetworkManager.Device.OvsPort',
  'org.freedesktop.NetworkManager.Device.Ppp',
  'org.freedesktop.NetworkManager.Device.Statistics',
  'org.freedesktop.NetworkManager.Device.Team',
  'org.freedesktop.NetworkManager.Device.Tun',
  'org.freedesktop.NetworkManager.Device.Veth',
  'org.freedesktop.NetworkManager.Device.Vlan',
  'org.freedesktop.NetworkManager.Device.Vrf',
  'org.freedesktop.NetworkManager.Device.Vxlan',
  'org.freedesktop.NetworkManager.Device.WiMax',
  'org.freedesktop.NetworkManager.Device.WifiP2P',
  'org.freedesktop.NetworkManager.Device.WireGuard',
  'org.freedesktop.NetworkManager.Device.Wired',
  'org.freedesktop.NetworkManager.Device.Wireless',
  'org.freedesktop.NetworkManager.Device.Wpan',
  'org.freedesktop.NetworkManager.DnsManager',
  'org.freedesktop.NetworkManager.IP4Config',
  'org.freedesktop.NetworkManager.IP6Config',
  'org.freedesktop.NetworkManager.PPP',
  'org.freedesktop.NetworkManager.SecretAgent',
  'org.freedesktop.NetworkManager.Settings',
  'org.freedesktop.NetworkManager.Settings.Connection',
  'org.freedesktop.NetworkManager.VPN.Connection',
  'org.freedesktop.NetworkManager.VPN.Plugin',
  'org.freedesktop.NetworkManager.WiMax.Nsp',
  'org.freedesktop.NetworkManager.WifiP2PPeer',
]

ifaces_xmls = []
sources = []
introspection_files = []
headers = []

foreach iface: ifaces
  iface_xml = iface + '.xml'
  ifaces_xmls += files(iface_xml)

  res = gnome.gdbus_codegen(
    iface,
    iface_xml,
    interface_prefix: 'org.freedesktop.NetworkManager',
    namespace: 'NMDBus',
    docbook: 'dbus',
  )

  sources += res

  if gio_unix_dep.version().version_compare('>= 2.51.3')
    dbus_iface_xml_path = join_paths(meson.current_build_dir(), 'dbus-' + iface_xml)
  else
    dbus_iface_xml_path = join_paths(build_root, 'dbus-' + iface_xml)
  endif

  content_files += dbus_iface_xml_path
  introspection_files += [ [res[2], dbus_iface_xml_path] ]
  headers += res[1]
endforeach

install_data(
  ifaces_xmls,
  install_dir: dbus_interfaces_dir,
)

libnmdbus = static_library(
  'nmdbus',
  sources: sources,
  include_directories: top_inc,
  c_args: introspection_extra_cflags,
  dependencies: glib_dep,
)

libnmdbus_dep = declare_dependency(
  sources: headers,
  include_directories: top_inc,
  dependencies: glib_dep,
)
