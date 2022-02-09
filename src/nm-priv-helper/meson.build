# SPDX-License-Identifier: LGPL-2.1-or-later

configure_file(
  input: 'org.freedesktop.nm_priv_helper.service.in',
  output: '@BASENAME@',
  install_dir: dbus_system_bus_services_dir,
  configuration: data_conf,
)

install_data(
  'nm-priv-helper.conf',
  install_dir: dbus_conf_dir,
)

executable(
  'nm-priv-helper',
  'nm-priv-helper.c',
  include_directories : [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
  ],
  link_with: [
    libnm_base,
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
