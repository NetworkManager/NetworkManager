# SPDX-License-Identifier: LGPL-2.1+

install_data(
  'nm-ifcfg-rh.conf',
  install_dir: dbus_conf_dir,
)

name = 'nmdbus-ifcfg-rh'

dbus_sources = gnome.gdbus_codegen(
  name,
  'nm-ifcfg-rh.xml',
  interface_prefix: 'com.redhat',
  namespace: 'NMDBus',
)

libnmdbus_ifcfg_rh = static_library(
  name,
  sources: dbus_sources,
  dependencies: glib_dep,
)

core_sources = files(
  'nms-ifcfg-rh-reader.c',
  'nms-ifcfg-rh-utils.c',
  'nms-ifcfg-rh-writer.c',
  'shvar.c',
)

libnms_ifcfg_rh_core = static_library(
  'nms-ifcfg-rh-core',
  sources: core_sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
)

sources = [dbus_sources] + core_sources + files(
  'nms-ifcfg-rh-storage.c',
  'nms-ifcfg-rh-plugin.c',
)

libnm_settings_plugin_ifcfg_rh = shared_module(
  'nm-settings-plugin-ifcfg-rh',
  sources: sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
  link_with: libnms_ifcfg_rh_core,
  link_args: ldflags_linker_script_settings,
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_settings_plugin_ifcfg_rh

data = [
  'nm-ifdown',
  'nm-ifup',
]

install_data(
  data,
  install_dir: nm_libexecdir,
  install_mode: 'rwxr-xr-x',
)

if enable_tests
  subdir('tests')
endif
