# SPDX-License-Identifier: LGPL-2.1-or-later

if enable_docs
  assert(enable_introspection, '-Ddocs=true requires -Dintrospection=true')

  merge_cmd = files(source_root / 'tools' / 'generate-docs-nm-settings-docs-merge.py')
  settings_docs_input_xml = custom_target(
    'settings-docs-input.xml',
    input: [merge_cmd, nm_settings_docs_xml_gir['nmcli'], nm_property_infos_xml['nmcli']],
    output: 'settings-docs-input.xml',
    command: [
      python_path,
      merge_cmd,
      '@OUTPUT@',
      nm_property_infos_xml['nmcli'],
      nm_settings_docs_xml_gir['nmcli'],
    ],
  )

  gen_cmd = files(source_root / 'tools' / 'generate-docs-settings-docs.py')
  settings_docs_source = custom_target(
    'settings-docs.h',
    input: [gen_cmd, settings_docs_input_xml],
    output: 'settings-docs.h',
    command: [
      python_path,
      gen_cmd,
      '--output', '@OUTPUT@',
      '--xml', settings_docs_input_xml
    ],
  )

  test(
    'check-settings-docs',
    find_program(join_paths(source_root, 'tools', 'check-compare-generated.sh')),
    args: [
      source_root + '/src/libnmc-setting/settings-docs.h.in',
      settings_docs_source,
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
