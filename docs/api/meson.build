doc_module = 'NetworkManager'

settings = 'settings-spec'
output = settings + '.xml'

settings_xml = custom_target(
  output,
  input: nm_settings_docs,
  output: output,
  command: [xsltproc, '--output', '@OUTPUT@', join_paths(meson.current_source_dir(), settings + '.xsl'), '@INPUT@']
)

configure_file(
  input: version_xml + '.in',
  output: version_xml,
  configuration: version_conf
)

content_files += join_paths(meson.source_root(), 'COPYING')

doc_path = join_paths(nm_datadir, 'gtk-doc', 'html', doc_module)

gnome.gtkdoc(
  doc_module,
  main_xml: 'network-manager-docs.xml',
  src_dir: meson.current_source_dir(),
  content_files: content_files,
  install: true,
  install_dir: doc_path
)
