# SPDX-License-Identifier: LGPL-2.1-or-later

dispatcher_inc = include_directories('.')

configure_file(
  input: 'org.freedesktop.nm_dispatcher.service.in',
  output: '@BASENAME@',
  install_dir: dbus_system_bus_services_dir,
  configuration: data_conf,
)

install_data(
  'nm-dispatcher.conf',
  install_dir: dbus_conf_dir,
)

libnm_dispatcher_core = static_library(
  'nm-dispatcher-core',
  sources: 'nm-dispatcher-utils.c',
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
    libnm_libnm_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="nm-dispatcher"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
)

nmdbus_dispatcher_sources = gnome.gdbus_codegen(
  'nmdbus-dispatcher',
  'nm-dispatcher.xml',
  interface_prefix: 'org.freedesktop',
  namespace: 'NMDBus',
)

executable(
  'nm-dispatcher',
  'nm-dispatcher.c',
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
    libnm_libnm_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="nm-dispatcher"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
  link_with: libnm_dispatcher_core,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
