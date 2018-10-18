doc_module = libnm_glib_name

private_headers = [
  'common.h',
  'nm-dbus-helpers-private.h',
  'nm-device-private.h',
  'nm-object-cache.h',
  'nm-object-private.h',
  'nm-remote-connection-private.h',
  'nm-types-private.h',
  'nm-secret-agent-glue.h',
  'nm-vpn-plugin-glue.h',
]

configure_file(
  input: version_xml + '.in',
  output: version_xml,
  configuration: version_conf,
)

gnome.gtkdoc(
  doc_module,
  main_xml: doc_module + '-docs.xml',
  src_dir: join_paths(meson.source_root(), 'libnm-glib'),
  dependencies: [
    libnm_glib_dep,
    libnm_glib_vpn_dep,
   ],
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
