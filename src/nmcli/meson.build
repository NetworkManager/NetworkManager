# SPDX-License-Identifier: LGPL-2.1-or-later

if enable_nmcli

# The file is called "nmcli-completion" but should be installed with
# name "nmcli". Currently it gets renamed by "tools/meson-post-install.sh",
# but if we depend on meson 0.46.0, we could use "rename" option.
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

generate_docs_nm_settings_nmcli = executable(
  'generate-docs-nm-settings-nmcli',
  files(
    'generate-docs-nm-settings-nmcli.c',
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
      'src/nmcli/generate-docs-nm-settings-nmcli.xml',
    ],
  )
else
  settings_docs_source = configure_file(
    input: 'generate-docs-nm-settings-nmcli.xml.in',
    output: '@BASENAME@',
    configuration: configuration_data(),
  )
endif
