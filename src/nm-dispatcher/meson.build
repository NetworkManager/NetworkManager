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

dispatcher_nmdbus_dispatcher_sources = gnome.gdbus_codegen(
  'nmdbus-dispatcher',
  'nm-dispatcher.xml',
  interface_prefix: 'org.freedesktop',
  namespace: 'NMDBus',
)

libnm_dispatcher_core = static_library(
  'nm-dispatcher-core',
  sources: 'nm-dispatcher-utils.c',
  dependencies: [
    libnm_dep,
  ],
)

executable(
  'nm-dispatcher',
  'nm-dispatcher.c',
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  link_with: [
    libnm_core_aux_extern,
    libnm_dispatcher_core,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)
