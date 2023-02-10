# SPDX-License-Identifier: LGPL-2.1-or-later

private_headers = [
  'nm-dbus-helpers.h',
  'nm-default-libnm.h',
  'nm-device-private.h',
  'nm-dhcp4-config.h',
  'nm-dhcp6-config.h',
  'nm-dns-manager.h',
  'nm-ip4-config.h',
  'nm-ip6-config.h',
  'nm-libnm-utils.h',
  'nm-object-private.h',
  'nm-remote-connection-private.h',

  'nm-connection-private.h',
  'nm-default-libnm-core.h',
  'nm-property-compare.h',
  'nm-setting-private.h',
  'nm-team-utils.h',
  'nm-utils-private.h',

  'nm-core-tests-enum-types.h',
  'test-general-enums.h',
]

scan_args = [
  '--rebuild-types',
  '--rebuild-sections',
  '--ignore-decorators=NM_AVAILABLE_IN_\d+_\d+|NM_DEPRECATED_IN_\d+_\d+|NM_DEPRECATED_IN_\d+_\d+_FOR\(\)',
  '--ignore-headers=' + ' '.join(private_headers),
]

version_xml = configure_file(
  input: 'version.xml.in',
  output: '@BASENAME@',
  configuration: data_conf,
)

gnome.gtkdoc(
  libnm_name,
  main_xml: libnm_name + '-docs.xml',
  src_dir: [
    libnm_core_public_inc,
    libnm_client_public_inc,
  ],
  dependencies: libnm_dep,
  scan_args: scan_args,
  scanobjs_args: '--type-init-func="g_type_init();"',
  fixxref_args: '--html-dir=' + join_paths(nm_prefix, gnome.gtkdoc_html_dir(libnm_name)),
  gobject_typesfile: libnm_name + '.types',
  html_assets: 'libnm.png',
  content_files: version_xml,
  install: true,
)
