doc_module = libnm_name

private_headers = [
  'common.h',
  'nm-crypto.h',
  'nm-crypto-impl.h',
  'nm-dbus-helpers.h',
  'nm-core-internal.h',
  'nm-core-types-internal.h',
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
  'nm-remote-settings.h',
  'nm-setting-private.h',
  'nm-utils-private.h',
  'nm-core-tests-enum-types.h',
  'nm-keyfile-internal.h',
  'nm-keyfile-utils.h',
  'test-general-enums.h',
]

configure_file(
  input: version_xml + '.in',
  output: version_xml,
  configuration: version_conf,
)

gnome.gtkdoc(
  doc_module,
  main_xml: doc_module + '-docs.xml',
  src_dir: [
    libnm_core_inc,
    libnm_inc,
  ],
  dependencies: libnm_dep,
  scan_args: [
    '--rebuild-types',
    '--rebuild-sections',
    '--ignore-headers=' + ' '.join(private_headers),
  ],
  scanobjs_args: '--type-init-func="g_type_init();"',
  fixxref_args: '--html-dir=' + join_paths(nm_prefix, gnome.gtkdoc_html_dir(doc_module)),
  gobject_typesfile: doc_module + '.types',
  html_assets: doc_module + '.png',
  install: true,
)
