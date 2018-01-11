dispatcher_inc = include_directories('.')

name = 'nm-dispatcher'

service_conf = configuration_data()
service_conf.set('sbindir', nm_sbindir)
service_conf.set('sysconfdir', nm_sysconfdir)
service_conf.set('localstatedir', nm_localstatedir)
service_conf.set('libexecdir', nm_libexecdir)

service = 'org.freedesktop.nm_dispatcher.service'

configure_file(
  input: service + '.in',
  output: service,
  install: true,
  install_dir: dbus_sys_dir,
  configuration: service_conf
)

install_data(
  'nm-dispatcher.conf',
  install_dir: dbus_conf_dir
)

sources = files('nm-dispatcher-utils.c')

deps = [
  libnm_dep,
  nm_core_dep
]

cflags = [
  '-DLIBEXECDIR="@0@"'.format(nm_libexecdir),
  '-DSYSCONFDIR="@0@"'.format(nm_sysconfdir),
  '-DNMCONFDIR="@0@"'.format(nm_pkgconfdir),
  '-DG_LOG_DOMAIN="@0@"'.format(name),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
]

libnm_dispatcher_core = static_library(
  name + '-core',
  sources: sources,
  dependencies: deps,
  c_args: cflags
)

sources = files('nm-dispatcher.c')

sources += gnome.gdbus_codegen(
  'nmdbus-dispatcher',
  name + '.xml',
  interface_prefix: 'org.freedesktop',
  namespace: 'NMDBus'
)

executable(
  name,
  sources,
  dependencies: deps,
  c_args: cflags,
  link_with: libnm_dispatcher_core,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir
)

if enable_tests
  subdir('tests')
endif
