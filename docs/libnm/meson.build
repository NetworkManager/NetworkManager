# SPDX-License-Identifier: LGPL-2.1-or-later

private_headers = [
  'common.h',
  'nm-core-internal.h',
  'nm-core-tests-enum-types.h',
  'nm-crypto-impl.h',
  'nm-crypto.h',
  'nm-dbus-helpers.h',
  'nm-default-libnm-core.h',
  'nm-device-private.h',
  'nm-dhcp4-config.h',
  'nm-dhcp6-config.h',
  'nm-dns-manager.h',
  'nm-ip4-config.h',
  'nm-ip6-config.h',
  'nm-manager.h',
  'nm-object-private.h',
  'nm-property-compare.h',
  'nm-remote-connection-private.h',
  'nm-setting-private.h',
  'nm-utils-private.h',

  'test-general-enums.h',

  'nm-keyfile-internal.h',
  'nm-keyfile-utils.h',

  'nm-auth-subject.h',
  'nm-common-macros.h',
  'nm-ethtool-base.h',
  'nm-libnm-core-utils.h',

  'nm-dispatcher-api.h',
  'nm-libnm-core-aux.h',
]

scan_args = [
  '--rebuild-types',
  '--rebuild-sections',
  '--ignore-decorators=NM_AVAILABLE_IN_\d_\d\d?|NM_DEPRECATED_IN_\d_\d\d?',
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
