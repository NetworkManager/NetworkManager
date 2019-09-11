dispatcher_inc = include_directories('.')

name = 'nm-dispatcher'

service_conf = configuration_data()
service_conf.set('sbindir', nm_sbindir)
service_conf.set('sysconfdir', nm_sysconfdir)
service_conf.set('localstatedir', nm_localstatedir)
service_conf.set('libexecdir', nm_libexecdir)

configure_file(
  input: 'org.freedesktop.nm_dispatcher.service.in',
  output: '@BASENAME@',
  install_dir: dbus_sys_dir,
  configuration: service_conf,
)

install_data(
  'nm-dispatcher.conf',
  install_dir: dbus_conf_dir,
)

deps = [
  libnm_dep,
  libnm_nm_default_dep,
]

c_flags = [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
]

libnm_dispatcher_core = static_library(
  name + '-core',
  sources: 'nm-dispatcher-utils.c',
  dependencies: deps,
  c_args: c_flags,
)

nmdbus_dispatcher_sources = gnome.gdbus_codegen(
  'nmdbus-dispatcher',
  name + '.xml',
  interface_prefix: 'org.freedesktop',
  namespace: 'NMDBus',
)

executable(
  name,
  name + '.c',
  dependencies: deps,
  c_args: c_flags,
  link_with: libnm_dispatcher_core,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
