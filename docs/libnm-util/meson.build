doc_module = 'libnm-util'

private_headers = [
  'crypto.h',
  'nm-setting-template.h',
  'nm-utils-private.h',
  'nm-setting-private.h',
  'nm-param-spec-specialized.h',
  'nm-test-utils.h',
  'nm-version.h'
]

configure_file(
  input: version_xml + '.in',
  output: version_xml,
  configuration: version_conf
)

doc_path = join_paths(nm_datadir, 'gtk-doc', 'html', doc_module)

gnome.gtkdoc(
  doc_module,
  main_xml: doc_module + '-docs.sgml',
  src_dir: libnm_util_inc,
  dependencies: libnm_util_dep,
  scan_args: [
    '--rebuild-types',
    '--rebuild-sections',
    '--ignore-headers=' + ' '.join(private_headers)
  ],
  scanobjs_args: '--type-init-func="g_type_init();"',
  fixxref_args: '--html-dir=' + doc_path,
  gobject_typesfile: doc_module + '.types',
  install: true,
  install_dir: doc_path
)
