sources = files(
  'nm-modem-broadband.c',
  'nm-modem.c',
  'nm-modem-manager.c',
  'nm-service-providers.c',
)

deps = [
  daemon_nm_default_dep,
  libsystemd_dep,
  mm_glib_dep,
]

if enable_ofono
  sources += files('nm-modem-ofono.c')
endif

linker_script = join_paths(meson.current_source_dir(), 'libnm-wwan.ver')

libnm_wwan = shared_module(
  'nm-wwan',
  sources: sources,
  dependencies: deps,
  c_args: daemon_c_flags,
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir,
)

wwan_inc = include_directories('.')

libnm_wwan_dep = declare_dependency(
  include_directories: wwan_inc,
  link_with: libnm_wwan,
)

core_plugins += libnm_wwan

test(
  'check-wwan',
  check_exports,
  args: [libnm_wwan.full_path(), linker_script],
)

sources = files(
  'nm-device-modem.c',
  'nm-wwan-factory.c',
)

libnm_device_plugin_wwan = shared_module(
  'nm-device-plugin-wwan',
  sources: sources,
  dependencies: deps,
  c_args: daemon_c_flags,
  link_with: libnm_wwan,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
  install_rpath: nm_plugindir,
)

core_plugins += libnm_device_plugin_wwan

run_target(
  'check-local-devices-wwan',
  command: [check_exports, libnm_device_plugin_wwan.full_path(), linker_script_devices],
  depends: libnm_device_plugin_wwan,
)

if enable_tests
  subdir('tests')
endif
