# SPDX-License-Identifier: LGPL-2.1-or-later

if enable_nmcli

install_data(
  'nmcli-completion',
  install_dir: join_paths(nm_datadir, 'bash-completion', 'completions'),
  rename: 'nmcli',
)

executable(
  'nmcli',
  files(
    'agent.c',
    'common.c',
    'connections.c',
    'devices.c',
    'general.c',
    'nmcli.c',
    'polkit-agent.c',
    'settings.c',
    'utils.c',
  ),
  dependencies: [
    libnm_dep,
    glib_dep,
    readline_dep,
  ],
  link_with: [
    libnmc_setting,
    libnmc_base,
    libnm_client_aux_extern,
    libnm_core_aux_extern,
    libnm_core_aux_intern,
    libnm_base,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
)

endif

gen_metadata_nm_settings_nmcli = executable(
  'gen-metadata-nm-settings-nmcli',
  files(
    'gen-metadata-nm-settings-nmcli.c',
  ),
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  link_with: [
    libnmc_setting,
    libnmc_base,
    libnm_core_aux_extern,
    libnm_core_aux_intern,
    libnm_base,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
)

if enable_docs
  gen_metadata_nm_settings_nmcli_xml = custom_target(
    'gen-metadata-nm-settings-nmcli.xml',
    output: 'gen-metadata-nm-settings-nmcli.xml',
    command: [ gen_metadata_nm_settings_nmcli ],
    capture: true,
  )

  test(
    'check-local-gen-metadata-nm-settings-nmcli',
    find_program(join_paths(source_root, 'tools', 'check-compare-generated.sh')),
    args: [
      source_root + '/src/nmcli/gen-metadata-nm-settings-nmcli.xml.in',
      gen_metadata_nm_settings_nmcli_xml,
    ],
  )
else
  gen_metadata_nm_settings_nmcli_xml = configure_file(
    input: 'gen-metadata-nm-settings-nmcli.xml.in',
    output: '@BASENAME@',
    configuration: configuration_data(),
  )
endif
