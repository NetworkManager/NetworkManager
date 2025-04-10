# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_client_impl_inc = include_directories('.')

libnm_client_impl_sources = files(
  'nm-access-point.c',
  'nm-active-connection.c',
  'nm-checkpoint.c',
  'nm-client.c',
  'nm-conn-utils.c',
  'nm-dbus-helpers.c',
  'nm-device-6lowpan.c',
  'nm-device-adsl.c',
  'nm-device-bond.c',
  'nm-device-bridge.c',
  'nm-device-bt.c',
  'nm-device-dummy.c',
  'nm-device-ethernet.c',
  'nm-device-generic.c',
  'nm-device-hsr.c',
  'nm-device-infiniband.c',
  'nm-device-ip-tunnel.c',
  'nm-device-ipvlan.c',
  'nm-device-loopback.c',
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

libnm_client_impl = static_library(
  'nm-client-impl',
  sources: libnm_client_impl_sources + libnm_client_public_enum_sources,
  dependencies: [
    libnmdbus_dep,
    libnm_core_public_dep,
    libnm_client_public_dep,
    libudev_dep,
    glib_dep,
  ],
)

linker_script = join_paths(meson.current_source_dir(), 'libnm.ver')

libnm = shared_library(
  'nm',
  version: libnm_version,
  dependencies: [
    libnm_core_public_dep,
    libnm_client_public_dep,
    libudev_dep,
    glib_dep,
  ],
  link_whole: [
    libnm_client_impl,
    libnm_core_aux_intern,
    libnm_core_impl,
    libnm_crypto,
    libnm_base,
    libnm_udev_aux,
    libnm_systemd_shared,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libnmdbus,
    libc_siphash,
  ],
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
)

libnm_dep = declare_dependency(
  dependencies: [
    libnm_core_public_dep,
    libnm_client_public_dep,
    glib_dep,
  ],
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

if enable_tests
  test(
    'check-local-exports-' + libnm_name,
    check_exports,
    args: [libnm.full_path(), linker_script],
  )
endif

if enable_introspection

  libnm_gir = gnome.generate_gir(
    libnm,
    sources: libnm_core_settings_sources + libnm_core_impl_sources + libnm_core_public_enum_sources + libnm_core_headers + libnm_client_impl_sources + libnm_client_headers + libnm_client_public_enum_sources + [nm_version_macro_header],
    includes: 'Gio-2.0',
    include_directories: [
      libnm_core_public_inc,
      libnm_client_public_inc,
      src_inc,
      top_inc,
    ],
    header: 'NetworkManager.h',
    dependencies: [
      declare_dependency(
        compile_args: [
          '-UGLIB_VERSION_MIN_REQUIRED',
          '-UGLIB_VERSION_MAX_ALLOWED',
        ],
      ),
    ],
    nsversion: nm_gir_version,
    namespace: 'NM',
    identifier_prefix: nm_id_prefix,
    symbol_prefix: nm_id_prefix.to_lower(),
    export_packages: libnm_name,
    extra_args: [
      '-DNETWORKMANAGER_COMPILATION',
    ],
    install: true,
  )

  gi_typelib_path = run_command('printenv', 'GI_TYPELIB_PATH', check: false).stdout()
  if gi_typelib_path != ''
    gi_typelib_path = ':' + gi_typelib_path
  endif
  gi_typelib_path = meson.current_build_dir() + gi_typelib_path

  ld_library_path = run_command('printenv', 'LD_LIBRARY_PATH', check: false).stdout()
  if ld_library_path != ''
    ld_library_path = ':' + ld_library_path
  endif
  ld_library_path = meson.current_build_dir() + ld_library_path

  gen_infos_cmd = files(source_root / 'tools' / 'generate-docs-nm-property-infos.py')
  gen_gir_cmd = files(source_root / 'tools' / 'generate-docs-nm-settings-docs-gir.py')

  names = [ 'dbus', 'nmcli', 'keyfile' ]
  if enable_ifcfg_rh
    names += [ 'ifcfg-rh' ]
  endif
  foreach name: names
    t_infos = custom_target(
      'nm-property-infos-' + name + '.xml',
      input: [gen_infos_cmd, libnm_gir[0]] + libnm_core_settings_sources,
      output: 'nm-property-infos-' + name + '.xml',
      command: [
        python_path,
        gen_infos_cmd,
        name,
        '@OUTPUT@',
        libnm_gir[0]
      ] + libnm_core_settings_sources,
    )

    t_gir = custom_target(
      'nm-settings-docs-gir-' + name + '.xml',
      input: [gen_gir_cmd, libnm_gir[0]],
      output: 'nm-settings-docs-gir-' + name + '.xml',
      command: [
        'env',
        'GI_TYPELIB_PATH=' + gi_typelib_path,
        'LD_LIBRARY_PATH=' + ld_library_path,
        python_path,
        gen_gir_cmd,
        '--gir', libnm_gir[0],
        '--output', '@OUTPUT@',
        '--target', name
      ],
      depends: libnm_gir,
    )

    # meson 0.47 doesn't support non-static keys for dicts
    # nor extending dicts incrementally. Workaround.
    if name == 'dbus'
      nm_property_infos_xml_dbus = t_infos
      nm_settings_docs_xml_gir_dbus = t_gir
    elif name == 'keyfile'
      nm_property_infos_xml_keyfile = t_infos
      nm_settings_docs_xml_gir_keyfile = t_gir
    elif name == 'ifcfg-rh'
      nm_property_infos_xml_ifcfg_rh = t_infos
      nm_settings_docs_xml_gir_ifcfg_rh = t_gir
    elif name == 'nmcli'
      nm_property_infos_xml_nmcli = t_infos
      nm_settings_docs_xml_gir_nmcli = t_gir
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
    nm_settings_docs_xml_gir = {
      'dbus':     nm_settings_docs_xml_gir_dbus,
      'keyfile':  nm_settings_docs_xml_gir_keyfile,
      'nmcli':    nm_settings_docs_xml_gir_nmcli,
      'ifcfg-rh': nm_settings_docs_xml_gir_ifcfg_rh,
    }
  else
    nm_property_infos_xml = {
      'dbus':    nm_property_infos_xml_dbus,
      'keyfile': nm_property_infos_xml_keyfile,
      'nmcli':   nm_property_infos_xml_nmcli,
    }
    nm_settings_docs_xml_gir = {
      'dbus':     nm_settings_docs_xml_gir_dbus,
      'keyfile':  nm_settings_docs_xml_gir_keyfile,
      'nmcli':    nm_settings_docs_xml_gir_nmcli,
    }
  endif
endif
