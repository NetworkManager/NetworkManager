common_inc = include_directories('.')

nm_polkit_listener = files('nm-polkit-listener.c')

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc
]

deps = [
  glib_dep,
  libnm_dep
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
  sources: sources + [libnm_core_enum[1]],
  include_directories: incs,
  dependencies: deps,
  c_args: cflags,
)

libnmc_base_dep = declare_dependency(
  link_with: libnmc_base,
  include_directories: common_inc
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
  sources: sources + [libnm_core_enum[1]],
  include_directories: incs,
  dependencies: deps,
  c_args: cflags,
  link_with: libnmc_base,
  link_depends: settings_docs_source
)

libnmc_dep = declare_dependency(
  link_with: libnmc,
  include_directories: common_inc
)

if (enable_introspection or enable_nmtui) and enable_tests
  subdir('tests')
endif
