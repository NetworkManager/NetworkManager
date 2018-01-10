doc_module = nm_name

settings = 'settings-spec'
output = settings + '.xml'

if enable_introspection
  settings_xml = custom_target(
    output,
    input: nm_settings_docs,
    output: output,
    command: [xsltproc, '--output', '@OUTPUT@', join_paths(meson.current_source_dir(), settings + '.xsl'), '@INPUT@'],
    # FIXME: there is no target depending on this, so it will not be built
    build_by_default: true
  )
endif

configure_file(
  input: version_xml + '.in',
  output: version_xml,
  configuration: version_conf
)

content_files += join_paths(meson.source_root(), 'COPYING')

gnome.gtkdoc(
  doc_module,
  main_xml: 'network-manager-docs.xml',
  src_dir: meson.current_source_dir(),
  content_files: content_files,
  install: true
)
