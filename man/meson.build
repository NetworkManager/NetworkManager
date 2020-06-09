# SPDX-License-Identifier: LGPL-2.1+

common_ent_file = configure_file(
  input: 'common.ent.in',
  output: '@BASENAME@',
  configuration: data_conf,
)

xsltproc_options = [
  xsltproc,
  '--output', '@OUTPUT@',
  '--path', meson.current_build_dir(),
  '--xinclude',
  '--nonet',
  '--stringparam', 'man.output.quietly', '1',
  '--stringparam', 'funcsynopsis.style', 'ansi',
  '--stringparam', 'man.th.extra1.suppress', '1',
  '--stringparam', 'man.authors.section.enabled', '0',
  '--stringparam', 'man.copyright.section.enabled', '0',
  '--stringparam', 'man.th.title.max.length', '30',
]

docbook_xls = 'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl'

mans_xmls = []

mans = [
  ['NetworkManager', '8'],
  ['NetworkManager.conf', '5'],
  ['nm-online', '1'],
  ['nmcli-examples', '7'],
  ['nmcli', '1'],
  ['nmtui', '1'],
  ['nm-initrd-generator', '8'],
]

if enable_ovs
  mans += [['nm-openvswitch', '7']]
endif

foreach man: mans
  input = man[0] + '.xml'
  content_files += join_paths(meson.current_source_dir(), input)

  output = '@0@.@1@'.format(man[0], man[1])

  custom_target(
    output,
    input: input,
    output: output,
    command: xsltproc_options + [docbook_xls, '@INPUT@'],
    depend_files: common_ent_file,
    install: true,
    install_dir: join_paths(nm_mandir, 'man' + man[1]),
  )
endforeach

if enable_introspection

  name = 'dbus'
  nm_settings_docs_xml_dbus = custom_target(
    'nm-settings-docs-' + name + '.xml',
    input: [nm_settings_docs_xml_gir, nm_property_infos_xml[name]],
    output: 'nm-settings-docs-' + name + '.xml',
    command: [
      python.path(),
      join_paths(meson.source_root(), 'libnm', 'generate-docs-nm-settings-docs-merge.py'),
      '@OUTPUT@',
      nm_property_infos_xml[name],
      nm_settings_docs_xml_gir,
    ],
    depends: libnm_gir,
  )

  name = 'nmcli'
  nm_settings_docs_xml_nmcli = custom_target(
    'nm-settings-docs-' + name + '.xml',
    input: [nm_settings_docs_xml_gir, nm_property_infos_xml[name]],
    output: 'nm-settings-docs-' + name + '.xml',
    command: [
      python.path(),
      join_paths(meson.source_root(), 'libnm', 'generate-docs-nm-settings-docs-merge.py'),
      '@OUTPUT@',
      nm_property_infos_xml[name],
      nm_settings_docs_xml_gir,
    ],
    depends: libnm_gir,
  )

  nm_settings_docs_xml = {
    'gir':   nm_settings_docs_xml_gir,
    'dbus':  nm_settings_docs_xml_dbus,
    'nmcli':  nm_settings_docs_xml_nmcli,
  }

  mans = [
    ['nm-settings-keyfile', '5', nm_property_infos_xml['keyfile']],
    ['nm-settings-dbus',    '5', nm_settings_docs_xml['dbus']],
    ['nm-settings-nmcli',   '5', nm_settings_docs_xml['nmcli']],
  ]

  if enable_ifcfg_rh
    mans += [['nm-settings-ifcfg-rh', '5', nm_property_infos_xml['ifcfg-rh']]]
  endif

  foreach man: mans
    output = man[0] + '.xml'

    input = custom_target(
      output,
      input: man[2],
      output: output,
      command: xsltproc_options + [join_paths(meson.current_source_dir(), man[0] + '.xsl'), '@INPUT@'],
    )
    content_files += input.full_path()

    output = '@0@.@1@'.format(man[0], man[1])

    custom_target(
      output,
      input: input,
      output: output,
      command: xsltproc_options + [docbook_xls, '@INPUT@'],
      install: true,
      install_dir: join_paths(nm_mandir, 'man' + man[1]),
    )
  endforeach
endif
