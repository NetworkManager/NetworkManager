common_inc = include_directories('.')

nm_polkit_listener = files('nm-polkit-listener.c')

deps = [
  libnm_dep,
  shared_nm_libnm_core_aux_dep,
]

cflags = clients_cflags + [
  '-DG_LOG_DOMAIN="libnmc"',
]

libnmc_base = static_library(
  'nmc-base',
  sources: files(
    'nm-client-utils.c',
    'nm-secret-agent-simple.c',
    'nm-vpn-helpers.c',
  ),
  dependencies: deps,
  c_args: cflags,
)

libnmc_base_dep = declare_dependency(
  include_directories: common_inc,
  link_with: libnmc_base,
)

settings_docs = 'settings-docs.h'

if enable_introspection
  settings_docs_source = custom_target(
    settings_docs,
    input: nm_property_docs,
    output: settings_docs,
    command: [xsltproc, '--output', '@OUTPUT@', join_paths(meson.current_source_dir(), 'settings-docs.xsl'), '@INPUT@'],
  )

  test(
    'check-settings-docs',
    find_program(join_paths(meson.source_root(), 'tools', 'check-settings-docs.sh')),
    args: [meson.source_root(), meson.build_root(), 'clients/common/' + settings_docs]
  )
else
  settings_docs_source = configure_file(
    input: settings_docs + '.in',
    output: settings_docs,
    configuration: configuration_data(),
  )
endif

libnmc = static_library(
  'nmc',
  sources: files(
    'nm-meta-setting-access.c',
    'nm-meta-setting-desc.c',
  ) + shared_nm_meta_setting_c + [settings_docs_source],
  dependencies: deps,
  c_args: cflags,
  link_with: libnmc_base,
  link_depends: settings_docs_source,
)

libnmc_dep = declare_dependency(
  include_directories: common_inc,
  link_with: libnmc,
)

if (enable_introspection or enable_nmtui) and enable_tests
  subdir('tests')
endif
