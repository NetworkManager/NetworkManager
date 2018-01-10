common_inc = include_directories('.')

nm_polkit_listener = files('nm-polkit-listener.c')

deps = [
  libnm_dep,
  nm_core_dep
]

cflags = clients_cflags + [
  '-DG_LOG_DOMAIN="libnmc"',
]

sources = shared_utils + files(
  'nm-client-utils.c',
  'nm-secret-agent-simple.c',
  'nm-vpn-helpers.c'
)

libnmc_base = static_library(
  'nmc-base',
  sources: sources,
  dependencies: deps,
  c_args: cflags
)

libnmc_base_dep = declare_dependency(
  include_directories: common_inc,
  link_with: libnmc_base
)

sources = shared_meta_setting + files(
  'nm-meta-setting-access.c',
  'nm-meta-setting-desc.c'
)

settings_docs = 'settings-docs.c'

if enable_introspection
  settings_docs_source = custom_target(
    settings_docs,
    input: nm_property_docs,
    output: settings_docs,
    command: [xsltproc, '--output', '@OUTPUT@', join_paths(meson.current_source_dir(), 'settings-docs.xsl'), '@INPUT@']
  )

  # FIXME: if enabled the check happens even if the settings_docs_source is not set
  '''
  if get_option('check_settings_docs')
    res = run_command(find_program('cmp'), '-s', settings_docs + '.in', settings_docs_source.full_path())
    if res.returncode() != 0
      message('The generated file ' + settings_docs_source.full_path() + ' differs from the source file ' + settings_docs + '.in' + '. You probably should copy the generated file over to the source file. You can skip this test by setting -Dcheck_settings_docs=false')
    endif
  endif
  '''
else
  settings_docs_source = configure_file(
    input: settings_docs + '.in',
    output: settings_docs,
    configuration: configuration_data()
  )
endif
sources += settings_docs_source

libnmc = static_library(
  'nmc',
  sources: sources,
  dependencies: deps,
  c_args: cflags,
  link_with: libnmc_base,
  link_depends: settings_docs_source
)

libnmc_dep = declare_dependency(
  include_directories: common_inc,
  link_with: libnmc
)

if (enable_introspection or enable_nmtui) and enable_tests
  subdir('tests')
endif
