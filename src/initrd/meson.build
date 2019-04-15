sources = files(
  'nmi-cmdline-reader.c',
  'nmi-ibft-reader.c',
)

nm_cflags = ['-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DAEMON']

libnmi_core = static_library(
  'nmi-core',
  c_args: nm_cflags,
  sources: sources,
  include_directories: src_inc,
  dependencies: libnm_core_dep,
)

name = 'nm-initrd-generator'
executable(
  name,
  name + '.c',
  c_args: nm_cflags,
  include_directories: src_inc,
  dependencies: [ libnm_core_dep ],
  link_with: [libnetwork_manager_base, libnmi_core],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
