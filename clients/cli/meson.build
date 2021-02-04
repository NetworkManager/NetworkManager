# SPDX-License-Identifier: LGPL-2.1-or-later

if enable_nmcli

# FIXME: nmcli-completion should be renamed to nmcli
install_data(
  'nmcli-completion',
  install_dir: join_paths(nm_datadir, 'bash-completion', 'completions'),
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
    libnmc_base_dep,
    libnmc_dep,
    readline_dep,
    libnm_libnm_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="nmcli"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
)

endif

generate_docs_nm_settings_nmcli = executable(
  'generate-docs-nm-settings-nmcli',
  files(
    'generate-docs-nm-settings-nmcli.c',
  ),
  dependencies: [
    libnmc_base_dep,
    libnmc_dep,
    libnm_libnm_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="nmcli"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
)

if enable_docs
  generate_docs_nm_settings_nmcli_xml = custom_target(
    'generate-docs-nm-settings-nmcli.xml',
    output: 'generate-docs-nm-settings-nmcli.xml',
    command: [ generate_docs_nm_settings_nmcli ],
    capture: true,
  )

  test(
    'check-local-generate-docs-nm-settings-nmcli',
    find_program(join_paths(source_root, 'tools', 'check-compare-generated.sh')),
    args: [
      source_root,
      build_root,
      'clients/cli/generate-docs-nm-settings-nmcli.xml',
    ],
  )
else
  settings_docs_source = configure_file(
    input: 'generate-docs-nm-settings-nmcli.xml.in',
    output: '@BASENAME@',
    configuration: configuration_data(),
  )
endif
