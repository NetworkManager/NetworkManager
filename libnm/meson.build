# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_inc = include_directories('.')

libnm_nm_default_dep = declare_dependency(
  sources: libnm_core_enum_sources[1],
  include_directories: libnm_inc,
  dependencies: libnm_core_nm_default_dep,
)

libnm_headers = files(
  'NetworkManager.h',
  'nm-access-point.h',
  'nm-active-connection.h',
  'nm-autoptr.h',
  'nm-checkpoint.h',
  'nm-client.h',
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
  'nm-types.h',
  'nm-vpn-connection.h',
  'nm-vpn-editor.h',
  'nm-vpn-plugin-old.h',
  'nm-vpn-service-plugin.h',
  'nm-wifi-p2p-peer.h',
  'nm-wimax-nsp.h',
)

install_headers(
  libnm_core_headers + libnm_headers + [nm_version_macro_header],
  subdir: libnm_name,
)

libnm_enum_sources = gnome.mkenums(
  'nm-enum-types',
  sources: libnm_headers + [nm_version_macro_header],
  identifier_prefix: nm_id_prefix,
  c_template: 'nm-enum-types.c.template',
  h_template: 'nm-enum-types.h.template',
  install_header: true,
  install_dir: libnm_pkgincludedir,
)

libnm_sources = files(
  'nm-access-point.c',
  'nm-active-connection.c',
  'nm-checkpoint.c',
  'nm-client.c',
  'nm-dbus-helpers.c',
  'nm-device-6lowpan.c',
  'nm-device-adsl.c',
  'nm-device-bond.c',
  'nm-device-bridge.c',
  'nm-device-bt.c',
  'nm-device-dummy.c',
  'nm-device-ethernet.c',
  'nm-device-generic.c',
  'nm-device-infiniband.c',
  'nm-device-ip-tunnel.c',
  'nm-device-macsec.c',
  'nm-device-macvlan.c',
  'nm-device-modem.c',
  'nm-device-olpc-mesh.c',
  'nm-device-ovs-bridge.c',
  'nm-device-ovs-interface.c',
  'nm-device-ovs-port.c',
  'nm-device-ppp.c',
  'nm-device-team.c',
  'nm-device-tun.c',
  'nm-device-veth.c',
  'nm-device-vlan.c',
  'nm-device-vrf.c',
  'nm-device-vxlan.c',
  'nm-device-wifi-p2p.c',
  'nm-device-wifi.c',
  'nm-device-wimax.c',
  'nm-device-wireguard.c',
  'nm-device-wpan.c',
  'nm-device.c',
  'nm-dhcp-config.c',
  'nm-dhcp4-config.c',
  'nm-dhcp6-config.c',
  'nm-dns-manager.c',
  'nm-ip-config.c',
  'nm-ip4-config.c',
  'nm-ip6-config.c',
  'nm-libnm-utils.c',
  'nm-object.c',
  'nm-remote-connection.c',
  'nm-secret-agent-old.c',
  'nm-vpn-connection.c',
  'nm-vpn-editor.c',
  'nm-vpn-plugin-old.c',
  'nm-vpn-service-plugin.c',
  'nm-wifi-p2p-peer.c',
  'nm-wimax-nsp.c',
)

libnm_static = static_library(
  'nm-static',
  sources: libnm_sources + libnm_enum_sources,
  dependencies: [
    libnmdbus_dep,
    libnm_libnm_core_intern_dep,
    libnm_nm_default_dep,
    libnm_keyfile_dep,
    libnm_udev_aux_dep,
    libudev_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="libnm"',
  ],
  link_with: libnm_systemd_logging_stub,
)

linker_script = join_paths(meson.current_source_dir(), 'libnm.ver')

libnm = shared_library(
  'nm',
  version: libnm_version,
  dependencies: libnm_nm_default_dep,
  link_whole: [
    libnm_static,
    libnm_core,
    libnm_keyfile,
    libnmdbus,
    libnm_systemd_logging_stub,
    libnm_glib_aux,
  ],
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
)

libnm_dep = declare_dependency(
  sources: libnm_enum_sources[1],
  include_directories: libnm_inc,
  link_with: libnm,
)

pkg.generate(
  libraries: libnm,
  version: nm_version,
  name: libnm_name,
  description: 'Convenience library for clients of NetworkManager',
  filebase: libnm_name,
  subdirs: libnm_name,
  requires: 'gio-2.0',
  variables: [
    'exec_prefix=${prefix}',
    'vpnservicedir=' + join_paths('${prefix}', 'lib', nm_name, 'VPN'),
  ],
)

test(
  'check-local-exports-' + libnm_name,
  check_exports,
  args: [libnm.full_path(), linker_script],
)

if enable_introspection

  libnm_gir = gnome.generate_gir(
    libnm,
    sources: libnm_core_sources + nm_keyfile_source + libnm_core_headers + libnm_core_enum_sources + libnm_sources + libnm_headers + libnm_enum_sources + [nm_version_macro_header],
    includes: 'Gio-2.0',
    nsversion: nm_gir_version,
    namespace: 'NM',
    identifier_prefix: nm_id_prefix,
    symbol_prefix: nm_id_prefix.to_lower(),
    header: 'NetworkManager.h',
    export_packages: libnm_name,
    extra_args: [
      '-DG_LOG_DOMAIN="libnm"',
      '-DNETWORKMANAGER_COMPILATION',
    ],
    install: true,
  )

  infos = [ 'dbus', 'nmcli', 'keyfile' ]
  if enable_ifcfg_rh
    infos += [ 'ifcfg-rh' ]
  endif
  foreach info: infos
    t = custom_target(
      'nm-propery-infos-' + info + '.xml',
      input: libnm_core_settings_sources,
      output: 'nm-propery-infos-' + info + '.xml',
      command: [
        perl,
        join_paths(meson.source_root(), 'tools', 'generate-docs-nm-property-infos.pl'),
        info,
        '@OUTPUT@',
        '@INPUT@'
      ],
    )

    # meson 0.47 doesn't support non-static keys for dicts
    # nor extending dicts incrementally. Workaround.
    if info == 'dbus'
      nm_property_infos_xml_dbus = t
    elif info == 'keyfile'
      nm_property_infos_xml_keyfile = t
    elif info == 'ifcfg-rh'
      nm_property_infos_xml_ifcfg_rh = t
    elif info == 'nmcli'
      nm_property_infos_xml_nmcli = t
    else
      assert(false)
    endif
  endforeach
  if enable_ifcfg_rh
    nm_property_infos_xml = {
      'dbus':     nm_property_infos_xml_dbus,
      'keyfile':  nm_property_infos_xml_keyfile,
      'nmcli':    nm_property_infos_xml_nmcli,
      'ifcfg-rh': nm_property_infos_xml_ifcfg_rh,
    }
  else
    nm_property_infos_xml = {
      'dbus':    nm_property_infos_xml_dbus,
      'keyfile': nm_property_infos_xml_keyfile,
      'nmcli':   nm_property_infos_xml_nmcli,
    }
  endif

  gi_typelib_path = run_command('printenv', 'GI_TYPELIB_PATH').stdout()
  if gi_typelib_path != ''
    gi_typelib_path = ':' + gi_typelib_path
  endif
  gi_typelib_path = meson.current_build_dir() + gi_typelib_path

  ld_library_path = run_command('printenv', 'LD_LIBRARY_PATH').stdout()
  if ld_library_path != ''
    ld_library_path = ':' + ld_library_path
  endif
  ld_library_path = meson.current_build_dir() + ld_library_path

  generate_setting_docs_env = [
    'env',
    'GI_TYPELIB_PATH=' + gi_typelib_path,
    'LD_LIBRARY_PATH=' + ld_library_path,
  ]

  nm_settings_docs_xml_gir = custom_target(
    'nm-settings-docs-gir.xml',
    input: libnm_gir[0],
    output: 'nm-settings-docs-gir.xml',
    command: [
      generate_setting_docs_env,
      python.path(),
      join_paths(meson.source_root(), 'tools', 'generate-docs-nm-settings-docs-gir.py'),
      '--lib-path', meson.current_build_dir(),
      '--gir', '@INPUT@',
      '--output', '@OUTPUT@'
    ],
    depends: libnm_gir,
  )

endif

libnm_libnm_aux = static_library(
  'nm-libnm-aux',
  sources: files(
    'nm-libnm-aux/nm-libnm-aux.c',
  ),
  c_args: [
    '-DG_LOG_DOMAIN="libnmc"',
  ],
  dependencies: [
    libnm_core_nm_default_dep,
    libnm_libnm_core_intern_dep,
    libnm_dep,
  ],
)

libnm_libnm_aux_dep = declare_dependency(
  include_directories: [shared_inc],
  link_with: [libnm_libnm_aux],
)

if enable_tests
  subdir('tests')
endif
