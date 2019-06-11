libnm_core_inc = include_directories('.')

libnm_core_headers = files(
  'nm-connection.h',
  'nm-core-types.h',
  'nm-dbus-interface.h',
  'nm-errors.h',
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
  'nm-setting-ovs-interface.h',
  'nm-setting-ovs-dpdk.h',
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
  'nm-setting-vlan.h',
  'nm-setting-vpn.h',
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

libnm_core_settings_sources = files(
  'nm-setting-6lowpan.c',
  'nm-setting-8021x.c',
  'nm-setting-adsl.c',
  'nm-setting-bluetooth.c',
  'nm-setting-bond.c',
  'nm-setting-bridge-port.c',
  'nm-setting-bridge.c',
  'nm-setting-cdma.c',
  'nm-setting-connection.c',
  'nm-setting-dcb.c',
  'nm-setting-dummy.c',
  'nm-setting-ethtool.c',
  'nm-setting-generic.c',
  'nm-setting-gsm.c',
  'nm-setting-infiniband.c',
  'nm-setting-ip-config.c',
  'nm-setting-ip-tunnel.c',
  'nm-setting-ip4-config.c',
  'nm-setting-ip6-config.c',
  'nm-setting-macsec.c',
  'nm-setting-macvlan.c',
  'nm-setting-match.c',
  'nm-setting-olpc-mesh.c',
  'nm-setting-ovs-bridge.c',
  'nm-setting-ovs-interface.c',
  'nm-setting-ovs-dpdk.c',
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
  'nm-setting-vlan.c',
  'nm-setting-vpn.c',
  'nm-setting-vxlan.c',
  'nm-setting-wifi-p2p.c',
  'nm-setting-wimax.c',
  'nm-setting-wired.c',
  'nm-setting-wireguard.c',
  'nm-setting-wireless-security.c',
  'nm-setting-wireless.c',
  'nm-setting-wpan.c',
)

libnm_core_sources = libnm_core_settings_sources + files(
  'nm-connection.c',
  'nm-crypto.c',
  'nm-dbus-utils.c',
  'nm-errors.c',
  'nm-keyfile-utils.c',
  'nm-keyfile.c',
  'nm-property-compare.c',
  'nm-setting.c',
  'nm-simple-connection.c',
  'nm-team-utils.c',
  'nm-utils.c',
  'nm-vpn-editor-plugin.c',
  'nm-vpn-plugin-info.c',
)

enum_headers = libnm_core_headers + [version_header]
enum_types = 'nm-core-enum-types'

libnm_core_enum = gnome.mkenums(
  enum_types,
  sources: enum_headers,
  identifier_prefix: nm_id_prefix,
  c_template: enum_types + '.c.template',
  h_template: enum_types + '.h.template',
  install_header: true,
  install_dir: libnm_pkgincludedir,
)

libnm_core_enum_dep = declare_dependency(
  sources: libnm_core_enum[1],
)

###############################################################################

shared_nm_libnm_core_intern = static_library(
    'nm-libnm-core-intern',
    sources: files('../shared/nm-libnm-core-intern/nm-ethtool-utils.c',
                   '../shared/nm-libnm-core-intern/nm-libnm-core-utils.c'),
    c_args: [
        '-DG_LOG_DOMAIN="@0@"'.format(libnm_name),
        '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM_CORE',
    ],
    include_directories: [
        top_inc,
        shared_inc,
        libnm_core_inc,
    ],
    dependencies: [
        glib_dep,
        shared_c_siphash_dep,
        shared_nm_glib_aux_dep,
        libnm_core_enum_dep,
    ],
)

shared_nm_libnm_core_intern_dep = declare_dependency(
    link_with: shared_nm_libnm_core_intern,
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: [
        glib_dep,
        shared_nm_glib_aux_dep,
        libnm_systemd_shared_dep,
    ],
)

###############################################################################

deps = [
  dl_dep,
  libudev_dep,
  uuid_dep,
  glib_dep,
  shared_c_siphash_dep,
  shared_nm_glib_aux_dep,
  shared_nm_udev_aux_dep,
  shared_nm_libnm_core_intern_dep,
]

cflags = [
  '-DG_LOG_DOMAIN="@0@"'.format(libnm_name),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM_CORE',
]

if enable_json_validation
  libnm_core_sources += files('nm-json.c')
  deps += jansson_dep
endif

if (crypto_gnutls_dep.found())
  libnm_crypto_gnutls = static_library(
    'nm-crypto-gnutls',
    sources: [ 'nm-crypto-gnutls.c' ],
    dependencies: deps + [ crypto_gnutls_dep ],
    c_args: cflags,
  )
endif

if (crypto_nss_dep.found())
  libnm_crypto_nss = static_library(
    'nm-crypto-nss',
    sources: [ 'nm-crypto-nss.c' ],
    dependencies: deps + [ crypto_nss_dep ],
    c_args: cflags,
  )
endif

if crypto == 'gnutls'
  libnm_crypto = libnm_crypto_gnutls
elif crypto == 'nss'
  libnm_crypto = libnm_crypto_nss
else
  error('bug')
endif

libnm_core_sources_all =  libnm_core_sources
libnm_core_sources_all += libnm_core_enum
libnm_core_sources_all += shared_nm_meta_setting_c
libnm_core_sources_all += [version_header]

libnm_core = static_library(
  'nm-core',
  sources: libnm_core_sources_all,
  dependencies: deps,
  link_with: libnm_crypto,
  c_args: cflags,
)

libnm_core_dep = declare_dependency(
  sources: libnm_core_enum[1],
  include_directories: libnm_core_inc,
  dependencies: [
    shared_nm_libnm_core_intern_dep,
    shared_nm_glib_aux_dep,
    shared_c_siphash_dep,
    libnm_systemd_shared_dep,
  ],
)

###############################################################################

shared_nm_libnm_core_aux = static_library(
    'nm-libnm-core-aux',
    sources: files('../shared/nm-libnm-core-aux/nm-libnm-core-aux.c'),
    c_args: [
        '-DG_LOG_DOMAIN="@0@"'.format(libnm_name),
        '-DNETWORKMANAGER_COMPILATION=(NM_NETWORKMANAGER_COMPILATION_WITH_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_LIB)',
    ],
    include_directories: [
        top_inc,
        shared_inc,
        libnm_core_inc,
    ],
    dependencies: [
        glib_dep,
        shared_c_siphash_dep,
        shared_nm_glib_aux_dep,
        libnm_core_dep,
    ],
)

shared_nm_libnm_core_aux_dep = declare_dependency(
    link_with: shared_nm_libnm_core_aux,
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: [
        libnm_core_dep,
        glib_dep,
        shared_nm_glib_aux_dep,
        libnm_systemd_shared_dep,
    ],
)

###############################################################################

enums_to_docbook = join_paths(meson.source_root(), 'tools', 'enums-to-docbook.pl')

docbooks = [
  ['nm-dbus-types', 'nm-dbus-interface.h', 'NetworkManager D-Bus API Types'],
  ['nm-vpn-dbus-types', 'nm-vpn-dbus-interface.h', 'VPN Plugin D-Bus API Types'],
]

foreach docbook: docbooks
  output = docbook[0] + '.xml'

  xml = custom_target(
    output,
    input: docbook[1],
    output: output,
    capture: true,
    command: [perl, enums_to_docbook, docbook[0], docbook[2], '@INPUT@'],
    # FIXME: gtkdoc does not depend directly on this.
    #        https://github.com/mesonbuild/meson/pull/2806
    build_by_default: true,
  )

  content_files += xml.full_path()
endforeach

###############################################################################

if enable_tests
  subdir('tests')
endif
