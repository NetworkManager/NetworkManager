ifaces_secret_agent_xml = files('org.freedesktop.NetworkManager.SecretAgent.xml')

ifaces_vpn_plugin_xml = files('org.freedesktop.NetworkManager.VPN.Plugin.xml')

ifaces = [
  'org.freedesktop.NetworkManager.AccessPoint',
  'org.freedesktop.NetworkManager.AgentManager',
  'org.freedesktop.NetworkManager.Checkpoint',
  'org.freedesktop.NetworkManager.Connection.Active',
  'org.freedesktop.NetworkManager.Device.Adsl',
  'org.freedesktop.NetworkManager.Device.Bluetooth',
  'org.freedesktop.NetworkManager.Device.Bond',
  'org.freedesktop.NetworkManager.Device.Bridge',
  'org.freedesktop.NetworkManager.Device.Dummy',
  'org.freedesktop.NetworkManager.Device.Generic',
  'org.freedesktop.NetworkManager.Device.Infiniband',
  'org.freedesktop.NetworkManager.Device.IPTunnel',
  'org.freedesktop.NetworkManager.Device.Macsec',
  'org.freedesktop.NetworkManager.Device.Macvlan',
  'org.freedesktop.NetworkManager.Device.Modem',
  'org.freedesktop.NetworkManager.Device.OlpcMesh',
  'org.freedesktop.NetworkManager.Device.OvsInterface',
  'org.freedesktop.NetworkManager.Device.OvsPort',
  'org.freedesktop.NetworkManager.Device.OvsBridge',
  'org.freedesktop.NetworkManager.Device.Ppp',
  'org.freedesktop.NetworkManager.Device.Statistics',
  'org.freedesktop.NetworkManager.Device.Team',
  'org.freedesktop.NetworkManager.Device.Tun',
  'org.freedesktop.NetworkManager.Device.Veth',
  'org.freedesktop.NetworkManager.Device.Vlan',
  'org.freedesktop.NetworkManager.Device.Vxlan',
  'org.freedesktop.NetworkManager.Device.WiMax',
  'org.freedesktop.NetworkManager.Device.Wired',
  'org.freedesktop.NetworkManager.Device.Wireless',
  'org.freedesktop.NetworkManager.Device',
  'org.freedesktop.NetworkManager.DHCP4Config',
  'org.freedesktop.NetworkManager.DHCP6Config',
  'org.freedesktop.NetworkManager.DnsManager',
  'org.freedesktop.NetworkManager.IP4Config',
  'org.freedesktop.NetworkManager.IP6Config',
  'org.freedesktop.NetworkManager',
  'org.freedesktop.NetworkManager.PPP',
  'org.freedesktop.NetworkManager.SecretAgent',
  'org.freedesktop.NetworkManager.Settings.Connection',
  'org.freedesktop.NetworkManager.Settings',
  'org.freedesktop.NetworkManager.VPN.Connection',
  'org.freedesktop.NetworkManager.VPN.Plugin',
  'org.freedesktop.NetworkManager.WiMax.Nsp'
]

ifaces_xmls = []
sources = []

# FIXME?: DBUS_INTERFACE_DOCS/docbook files are generated in
# "meson.current_build_dir()" instead of "meson.source_root()/docs/api"
foreach iface: ifaces
  iface_xml = iface + '.xml'
  ifaces_xmls += files(iface_xml)

  sources += gnome.gdbus_codegen(
    iface,
    iface_xml,
    interface_prefix: 'org.freedesktop.NetworkManager',
    namespace: 'NMDBus',
    docbook: 'dbus'
  )

  # FIXME: gnome.gdbus_codegen should return the docbook as a target result
  content_files += join_paths(meson.current_build_dir(), 'dbus-' + iface_xml)
endforeach

install_data(
  ifaces_xmls,
  install_dir: dbus_ifaces_dir
)

'''
# gdbus-codegen 2.38 will emit code that requires glib 2.38, which
# will then cause availability warnings if we define
# GLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32.
#
# This is fixed in GLib 2.40 (it emits code that takes
# GLIB_VERSION_MAX_ALLOWED into account), so this workaround can go
# away when we depend on that.
introspection_libnmdbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(GLIB_CFLAGS))
'''

libnmdbus = static_library(
  'nmdbus',
  sources: sources,
  include_directories: top_inc,
  dependencies: glib_dep
)

libnmdbus_dep = declare_dependency(
  link_with: libnmdbus,
  include_directories: include_directories('.')
)
