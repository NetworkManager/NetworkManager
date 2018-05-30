libnm_util_inc = include_directories('.')

enums_headers = [version_header] + files(
  'nm-connection.h',
  'nm-setting-8021x.h',
  'nm-setting-adsl.h',
  'nm-setting-bluetooth.h',
  'nm-setting-bond.h',
  'nm-setting-bridge.h',
  'nm-setting-bridge-port.h',
  'nm-setting-cdma.h',
  'nm-setting-connection.h',
  'nm-setting-dcb.h',
  'nm-setting-generic.h',
  'nm-setting-gsm.h',
  'nm-setting.h',
  'nm-setting-infiniband.h',
  'nm-setting-ip4-config.h',
  'nm-setting-ip6-config.h',
  'nm-setting-olpc-mesh.h',
  'nm-setting-ppp.h',
  'nm-setting-pppoe.h',
  'nm-setting-serial.h',
  'nm-setting-team.h',
  'nm-setting-team-port.h',
  'nm-setting-vlan.h',
  'nm-setting-vpn.h',
  'nm-setting-wimax.h',
  'nm-setting-wired.h',
  'nm-setting-wireless.h',
  'nm-setting-wireless-security.h',
  'nm-utils.h',
  'nm-version.h'
)

headers = enums_headers + files(
  'NetworkManager.h',
  'NetworkManagerVPN.h'
)

install_headers(
  headers,
  subdir: nm_name
)

enum_types = 'nm-utils-enum-types'

libnm_utils_enum = gnome.mkenums(
  enum_types,
  sources: enums_headers,
  identifier_prefix: nm_id_prefix,
  c_template: enum_types + '.c.template',
  h_template: enum_types + '.h.template',
  install_header: true,
  install_dir: nm_pkgincludedir
)

sources = files(
  'crypto.c',
  'crypto_' + crypto + '.c',
  'nm-connection.c',
  'nm-param-spec-specialized.c',
  'nm-setting-8021x.c',
  'nm-setting-adsl.c',
  'nm-setting-bluetooth.c',
  'nm-setting-bridge.c',
  'nm-setting-bridge-port.c',
  'nm-setting-bond.c',
  'nm-setting.c',
  'nm-setting-cdma.c',
  'nm-setting-connection.c',
  'nm-setting-dcb.c',
  'nm-setting-generic.c',
  'nm-setting-gsm.c',
  'nm-setting-infiniband.c',
  'nm-setting-ip4-config.c',
  'nm-setting-ip6-config.c',
  'nm-setting-olpc-mesh.c',
  'nm-setting-ppp.c',
  'nm-setting-pppoe.c',
  'nm-setting-serial.c',
  'nm-setting-team.c',
  'nm-setting-team-port.c',
  'nm-setting-wimax.c',
  'nm-setting-wired.c',
  'nm-setting-wireless.c',
  'nm-setting-wireless-security.c',
  'nm-setting-vlan.c',
  'nm-setting-vpn.c',
  'nm-utils.c',
  'nm-value-transforms.c'
)
sources += shared_files_libnm_util

deps = [
  crypto_dep,
  dbus_dep,
  dbus_glib_dep,
  shared_dep,
  uuid_dep
]

common_cflags = [
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM_UTIL',
  '-DNMLOCALEDIR="@0@"'.format(nm_localedir),
]

cflags = common_cflags + [
  '-DG_LOG_DOMAIN="@0@"'.format(libnm_util_name)
]

linker_script = join_paths(meson.current_source_dir(), 'libnm-util.ver')

libnm_util = shared_library(
  'nm-util',
  sources: sources + libnm_utils_enum,
  version: libnm_util_version,
  dependencies: deps,
  c_args: cflags,
  link_args: [
    '-Wl,--version-script,@0@'.format(linker_script),
  ],
  link_depends: linker_script,
  install: true
)

libnm_util_dep = declare_dependency(
  sources: libnm_utils_enum[1],
  include_directories: libnm_util_inc,
  link_with: libnm_util
)

pkg.generate(
  libraries: libnm_util,
  version: nm_version,
  name: libnm_util_name,
  description: 'Convenience library for clients of NetworkManager',
  filebase: libnm_util_name,
  subdirs: nm_name,
  requires: 'NetworkManager >= ' + nm_version + ' glib-2.0 dbus-glib-1',
  variables: 'exec_prefix=${prefix}'
)

if enable_introspection
  gir_sources = sources + headers + libnm_utils_enum

  gir_includes = [
    'DBusGLib-1.0',
    'GObject-2.0'
  ]

  libnm_util_gir = gnome.generate_gir(
    libnm_util,
    sources: gir_sources,
    nsversion: nm_gir_version,
    namespace: nm_name,
    identifier_prefix: nm_id_prefix,
    symbol_prefix: nm_id_prefix.to_lower(),
    export_packages: libnm_util_name,
    includes: gir_includes,
    install: true
  )

  libnm_util_gir_dep = declare_dependency(
    sources: libnm_util_gir,
    link_with: libnm_util
  )
endif

run_target(
  'check-local-exports-' + libnm_util_name,
  command: [check_exports, libnm_util.full_path(), linker_script],
  depends: libnm_util
)

sources = files(
  'crypto.c',
  'crypto_' + crypto + '.c'
)

deps = [
  crypto_dep,
  shared_dep
]

libtest_crypto = static_library(
  'test-crypto',
  sources: sources,
  dependencies: deps,
  c_args: cflags
)

if enable_tests
  subdir('tests')
endif
