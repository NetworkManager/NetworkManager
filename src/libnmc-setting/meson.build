# SPDX-License-Identifier: LGPL-2.1-or-later

if enable_docs
  settings_docs_input_xml = custom_target(
    'settings-docs-input.xml',
    input: [nm_settings_docs_xml_gir, nm_property_infos_xml['nmcli']],
    output: 'settings-docs-input.xml',
    command: [
      python.path(),
      join_paths(meson.source_root(), 'tools', 'generate-docs-nm-settings-docs-merge.py'),
      '@OUTPUT@',
      nm_property_infos_xml['nmcli'],
      nm_settings_docs_xml_gir,
    ],
  )

  settings_docs_source = custom_target(
    'settings-docs.h',
    input: settings_docs_input_xml,
    output: 'settings-docs.h',
    command: [xsltproc, '--output', '@OUTPUT@', join_paths(meson.current_source_dir(), 'settings-docs.xsl'), '@INPUT@'],
  )

  test(
    'check-settings-docs',
    find_program(join_paths(source_root, 'tools', 'check-compare-generated.sh')),
    args: [
      source_root,
      build_root,
      'src/libnmc-setting/settings-docs.h',
    ],
  )
else
  settings_docs_source = configure_file(
    input: 'settings-docs.h.in',
    output: '@BASENAME@',
    configuration: configuration_data(),
  )
endif

libnmc_setting = static_library(
  'nmc-setting',
  sources: [settings_docs_source] + files(
    'nm-meta-setting-access.c',
    'nm-meta-setting-base-impl.c',
    'nm-meta-setting-desc.c',
  ),
  dependencies: [
    libnm_dep,
  ],
  link_depends: settings_docs_source,
)
