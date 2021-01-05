# SPDX-License-Identifier: LGPL-2.1+

sources = files(
  'nmi-cmdline-reader.c',
  'nmi-dt-reader.c',
  'nmi-ibft-reader.c',
)

libnmi_core = static_library(
  'nmi-core',
  sources: sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
)

name = 'nm-initrd-generator'

links = [
  libnetwork_manager_base,
  libnmi_core,
]

executable(
  name,
  name + '.c',
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
  link_with: links,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
