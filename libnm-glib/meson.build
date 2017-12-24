dbus_binding_tool = find_program('dbus-binding-tool')

common_incs = [
  top_inc,
  shared_inc
]

common_deps = [
  dbus_dep,
  dbus_glib_dep,
  glib_dep
]

common_cflags = [
  '-DG_LOG_DOMAIN="libnm-glib"',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_LEGACY'
]

libnm_glib_inc = include_directories('.')

vpn_headers = files(
  'nm-vpn-plugin.h',
  'nm-vpn-plugin-ui-interface.h',
  'nm-vpn-plugin-utils.h'
)

headers = files(
  'nm-access-point.h',
  'nm-active-connection.h',
  'nm-client.h',
  'nm-device-adsl.h',
  'nm-device-bond.h',
  'nm-device-bridge.h',
  'nm-device-bt.h',
  'nm-device-ethernet.h',
  'nm-device-generic.h',
  'nm-device.h',
  'nm-device-infiniband.h',
  'nm-device-modem.h',
  'nm-device-olpc-mesh.h',
  'nm-device-team.h',
  'nm-device-vlan.h',
  'nm-device-wifi.h',
  'nm-device-wimax.h',
  'nm-dhcp4-config.h',
  'nm-dhcp6-config.h',
  'nm-ip4-config.h',
  'nm-ip6-config.h',
  'nm-object.h',
  'nm-remote-connection.h',
  'nm-remote-settings.h',
  'nm-secret-agent.h',
  'nm-types.h',
  'nm-vpn-connection.h',
  'nm-wimax-nsp.h'
)

deprecated_headers = files('libnm_glib.h')

install_headers(
  headers + vpn_headers + deprecated_headers,
  subdir: 'libnm-glib'
)

incs = common_incs + [libnm_util_inc]

cflags = common_cflags + [
  '-Wno-deprecated-declarations',
  '-Wno-deprecated'
]

libdeprecated_nm_glib = static_library(
  'deprecated-nm-glib',
  sources: 'libnm_glib.c',
  include_directories: incs,
  dependencies: common_deps,
  c_args: cflags
)

sources = files(
  'nm-vpn-plugin.c',
  'nm-vpn-plugin-ui-interface.c',
  'nm-vpn-plugin-utils.c'
)

glue = 'nm-vpn-plugin-glue.h'

sources += custom_target(
  glue,
  input: ifaces_vpn_plugin_xml,
  output: glue,
  command: [dbus_binding_tool, '--prefix=nm_vpn_plugin', '--mode=glib-server', '--output=@OUTPUT@', '@INPUT@']
)

enum_types = 'nm-vpn-enum-types'

libnm_glib_vpn_enum = gnome.mkenums(
  enum_types,
  sources: vpn_headers,
  identifier_prefix: nm_id_prefix,
  c_template: enum_types + '.c.template',
  h_template: enum_types + '.h.template',
  install_header: true,
  install_dir: libnm_glib_pkgincludedir
)

deps = common_deps + [libnm_util_dep]

symbol_map = join_paths(meson.current_source_dir(), 'libnm-glib-vpn.ver')

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(symbol_map)
endif

libnm_glib_vpn = shared_library(
  'nm-glib-vpn',
  sources: sources + libnm_glib_vpn_enum + [libnm_utils_enum[1]],
  version: libnm_glib_vpn_version,
  include_directories: common_incs,
  dependencies: deps,
  c_args: common_cflags,
  link_args: ldflags,
  link_depends: symbol_map,
  install: true
)

libnm_glib_vpn_dep = declare_dependency(
  link_with: libnm_glib_vpn,
  include_directories: libnm_glib_inc
)

pkg.generate(
  libraries: libnm_glib_vpn,
  version: nm_version,
  name: 'libnm-glib-vpn',
  description: 'Convenience library for NetworkManager VPN plugins',
  filebase: 'libnm-glib-vpn',
  subdirs: 'libnm-glib',
  requires: 'NetworkManager >= ' + nm_version + ' glib-2.0 dbus-glib-1',
  variables: 'exec_prefix=${prefix}'
)

sources = shared_udev_utils + files(
  'nm-access-point.c',
  'nm-active-connection.c',
  'nm-client.c',
  'nm-dbus-helpers.c',
  'nm-device-adsl.c',
  'nm-device-bond.c',
  'nm-device-bridge.c',
  'nm-device-bt.c',
  'nm-device.c',
  'nm-device-ethernet.c',
  'nm-device-generic.c',
  'nm-device-infiniband.c',
  'nm-device-olpc-mesh.c',
  'nm-device-modem.c',
  'nm-device-team.c',
  'nm-device-vlan.c',
  'nm-device-wifi.c',
  'nm-device-wimax.c',
  'nm-dhcp4-config.c',
  'nm-dhcp6-config.c',
  'nm-ip4-config.c',
  'nm-ip6-config.c',
  'nm-object.c',
  'nm-object-cache.c',
  'nm-remote-connection.c',
  'nm-remote-settings.c',
  'nm-secret-agent.c',
  'nm-types.c',
  'nm-vpn-connection.c',
  'nm-wimax-nsp.c'
)

glue = 'nm-secret-agent-glue.h'

nm_secret_agent_glue = custom_target(
  glue,
  input: ifaces_secret_agent_xml,
  output: glue,
  command: [dbus_binding_tool, '--prefix=nm_secret_agent', '--mode=glib-server', '--output=@OUTPUT@', '@INPUT@']
)

enum_types = 'nm-glib-enum-types'

libnm_glib_enum = gnome.mkenums(
  enum_types,
  sources: headers,
  identifier_prefix: nm_id_prefix,
  c_template: enum_types + '.c.template',
  h_template: enum_types + '.h.template',
  install_header: true,
  install_dir: libnm_glib_pkgincludedir
)

deps = common_deps + [
  libudev_dep,
  libnm_util_dep
]

cflags = common_cflags + ['-DNMRUNDIR="@0@"'.format(nm_pkgrundir)]

symbol_map = join_paths(meson.current_source_dir(), 'libnm-glib.ver')

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(symbol_map)
endif

libnm_glib = shared_library(
  'nm-glib',
  sources: sources + libnm_glib_enum + [nm_secret_agent_glue, libnm_utils_enum[1]],
  version: libnm_glib_version,
  include_directories: common_incs,
  dependencies: deps,
  c_args: cflags,
  link_with: libdeprecated_nm_glib,
  link_args: ldflags,
  link_depends: symbol_map,
  install: true
)

libnm_glib_dep = declare_dependency(
  link_with: libnm_glib,
  include_directories: libnm_glib_inc
)

pkg.generate(
  libraries: libnm_glib,
  version: nm_version,
  name: 'libnm-glib',
  description: 'Convenience library for clients of NetworkManager',
  filebase: 'libnm-glib',
  subdirs: 'libnm-glib',
  requires: 'libnm-util >= ' + nm_version + ' NetworkManager >= ' + nm_version + ' gobject-2.0 dbus-glib-1',
  variables: 'exec_prefix=${prefix}'
)

if enable_introspection
  gir_sources = sources + headers + libnm_glib_enum

  deps = [
    dbus_glib_dep,
    libnm_glib_dep,
    libnm_util_gir_dep
  ]

  gir_includes = [
    'DBusGLib-1.0',
    'Gio-2.0'
  ]

  libnm_glib_gir = gnome.generate_gir(
    libnm_glib,
    sources: gir_sources,
    dependencies: deps,
    nsversion: nm_gir_version,
    namespace: 'NMClient',
    identifier_prefix: nm_id_prefix,
    symbol_prefix: nm_id_prefix.to_lower(),
    export_packages: ['libnm-glib', 'libnm-glib-vpn'],
    includes: gir_includes,
    extra_args: common_cflags + ['--include-uninstalled=' + libnm_util_gir[0].full_path()],
    install: true
  )
endif

name = 'libnm-glib-test'

deps = common_deps + [libnm_util_dep]

executable(
  name,
  [name + '.c', libnm_utils_enum[1]],
  include_directories: common_incs,
  dependencies: deps,
  c_args: common_cflags,
  link_with: libnm_glib
)

run_target(
  'check-local-exports-libnm-glib',
  command: [check_exports, libnm_glib.full_path(), symbol_map],
  depends: libnm_glib
)

if enable_tests
  subdir('tests')
endif
