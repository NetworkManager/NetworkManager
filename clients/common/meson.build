# SPDX-License-Identifier: LGPL-2.1-or-later

common_inc = include_directories('.')

libnmc_base = static_library(
  'nmc-base',
  sources: files(
    'nm-client-utils.c',
    'nm-secret-agent-simple.c',
    'nm-vpn-helpers.c',
    'nm-polkit-listener.c',
  ),
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="libnmc"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
)

libnmc_base_dep = declare_dependency(
  include_directories: common_inc,
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
  ],
  link_with: libnmc_base,
)

if enable_docs
  settings_docs_source = custom_target(
    'settings-docs.h',
    input: nm_settings_docs_xml_gir,
    output: 'settings-docs.h',
    command: [
      xsltproc,
      '--output',
      '@OUTPUT@',
      join_paths(meson.current_source_dir(), 'settings-docs.xsl'),
      '@INPUT@',
    ],
  )

  test(
    'check-settings-docs',
    find_program(join_paths(source_root, 'tools', 'check-compare-generated.sh')),
    args: [
      source_root,
      build_root,
      'clients/common/settings-docs.h',
    ],
  )
else
  settings_docs_source = configure_file(
    input: 'settings-docs.h.in',
    output: '@BASENAME@',
    configuration: configuration_data(),
  )
endif

libnmc = static_library(
  'nmc',
  sources: nm_meta_setting_source + [settings_docs_source] + files(
    'nm-meta-setting-access.c',
    'nm-meta-setting-desc.c',
  ),
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
    libnm_libnm_core_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="libnmc"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
  link_depends: settings_docs_source,
)

libnmc_dep = declare_dependency(
  include_directories: common_inc,
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
  ],
  link_with: libnmc,
)

if (enable_introspection or enable_nmtui) and enable_tests
  subdir('tests')
endif
