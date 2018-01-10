sources = files(
  'nm-modem-broadband.c',
  'nm-modem.c',
  'nm-modem-manager.c'
)

deps = [
  libsystemd_dep,
  mm_glib_dep,
  nm_dep
]

if enable_ofono
  sources += files('nm-modem-ofono.c')
endif

symbol_name = join_paths(meson.current_source_dir(), 'libnm-wwan.ver')

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(symbol_name)
endif

libnm_wwan = shared_module(
  'nm-wwan',
  sources: sources,
  dependencies: deps,
  link_args: ldflags,
  link_depends: symbol_name,
  install: true,
  install_dir: nm_pkglibdir
)

libnm_wwan_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: libnm_wwan
)

core_plugins += libnm_wwan

run_target(
  'check-wwan',
  command: [check_exports, libnm_wwan.full_path(), symbol_name],
  depends: libnm_wwan
)

sources = files(
  'nm-device-modem.c',
  'nm-wwan-factory.c'
)

deps += libnmdbus_dep

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(linker_script_devices)
endif

libnm_device_plugin_wwan = shared_module(
  'nm-device-plugin-wwan',
  sources: sources,
  dependencies: deps,
  link_with: libnm_wwan,
  link_args: ldflags,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_pkglibdir
)

core_plugins += libnm_device_plugin_wwan

run_target(
  'check-local-devices-wwan',
  command: [check_exports, libnm_device_plugin_wwan.full_path(), linker_script_devices],
  depends: libnm_device_plugin_wwan
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-wwan: src/devices/wwan/libnm-device-plugin-wwan.la src/devices/wwan/libnm-wwan.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/wwan/.libs/libnm-device-plugin-wwan.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/wwan/.libs/libnm-device-plugin-wwan.so)
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/wwan/.libs/libnm-wwan.so "$(srcdir)/src/devices/wwan/libnm-wwan.ver"
  $(call check_so_symbols,$(builddir)/src/devices/wwan/.libs/libnm-wwan.so)
'''
