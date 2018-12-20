doc_module = libnm_util_name

private_headers = [
  'crypto.h',
  'nm-utils-private.h',
  'nm-setting-private.h',
  'nm-param-spec-specialized.h',
  'nm-test-utils.h',
  'nm-version.h',
]

configure_file(
  input: version_xml + '.in',
  output: version_xml,
  configuration: version_conf,
)

gnome.gtkdoc(
  doc_module,
  main_xml: doc_module + '-docs.sgml',
  src_dir: libnm_util_inc,
  dependencies: libnm_util_dep,
  scan_args: [
    '--rebuild-types',
    '--rebuild-sections',
    '--ignore-headers=' + ' '.join(private_headers),
  ],
  scanobjs_args: '--type-init-func="g_type_init();"',
  fixxref_args: '--html-dir=' + join_paths(nm_prefix, gnome.gtkdoc_html_dir(doc_module)),
  gobject_typesfile: doc_module + '.types',
  install: true,
)
