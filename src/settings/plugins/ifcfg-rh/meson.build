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

# FIXME: check_so_symbols replacement
'''
run_target(
  'check-local-symbols-settings-ifcfg-rh',
  command: [check_so_symbols, libnm_settings_plugin_ifcfg_rh.full_path()],
  depends: libnm_settings_plugin_ifcfg_rh,
)

check-local-symbols-settings-ifcfg-rh: src/settings/plugins/ifcfg-rh/libnm-settings-plugin-ifcfg-rh.la
  $(call check_so_symbols,$(builddir)/src/settings/plugins/ifcfg-rh/.libs/libnm-settings-plugin-ifcfg-rh.so)
'''

data = [
  'nm-ifdown',
  'nm-ifup',
]

install_data(
  data,
  install_dir: nm_libexecdir,
  install_mode: 'rwxr-xr-x',
)

meson.add_install_script('sh', '-c',
                         'mkdir -p $DESTDIR/@0@/sysconfig/network-scripts'.format(nm_sysconfdir))

if enable_tests
  subdir('tests')
endif
