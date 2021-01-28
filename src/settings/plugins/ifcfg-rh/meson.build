# SPDX-License-Identifier: LGPL-2.1-or-later

install_data(
  'nm-ifcfg-rh.conf',
  install_dir: dbus_conf_dir,
)

dbus_sources = gnome.gdbus_codegen(
  'nmdbus-ifcfg-rh',
  'nm-ifcfg-rh.xml',
  interface_prefix: 'com.redhat',
  namespace: 'NMDBus',
)

libnmdbus_ifcfg_rh = static_library(
  'nmdbus-ifcfg-rh',
  sources: dbus_sources,
  dependencies: glib_dep,
  c_args: introspection_extra_cflags,
)

libnms_ifcfg_rh_core = static_library(
  'nms-ifcfg-rh-core',
  sources: files(
    'nms-ifcfg-rh-reader.c',
    'nms-ifcfg-rh-utils.c',
    'nms-ifcfg-rh-writer.c',
    'shvar.c',
  ),
  dependencies: core_default_dep,
  c_args: daemon_c_flags,
)

libnm_settings_plugin_ifcfg_rh = shared_module(
  'nm-settings-plugin-ifcfg-rh',
  sources: files(
    'nms-ifcfg-rh-storage.c',
    'nms-ifcfg-rh-plugin.c',
  ),
  dependencies: core_plugin_dep,
  c_args: daemon_c_flags,
  link_with: libnms_ifcfg_rh_core,
  link_args: ldflags_linker_script_settings,
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_settings_plugin_ifcfg_rh

install_data(
  [
    'nm-ifdown',
    'nm-ifup',
  ],
  install_dir: nm_libexecdir,
  install_mode: 'rwxr-xr-x',
)

if enable_tests
  subdir('tests')
endif
