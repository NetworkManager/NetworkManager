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

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc
]

deps = [
  glib_dep,
  libnm_dep
]

cflags = [
  '-DLIBEXECDIR="@0@"'.format(nm_libexecdir),
  '-DSYSCONFDIR="@0@"'.format(nm_sysconfdir),
  '-DNMCONFDIR="@0@"'.format(nm_pkgconfdir)
]

libnm_dispatcher_core = static_library(
  name + '-core',
  sources: sources,
  include_directories: incs,
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

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(linker_script_binary)
endif

executable(
  name,
  sources,
  include_directories: incs,
  dependencies: deps,
  c_args: cflags,
  link_with: libnm_dispatcher_core,
  link_args: ldflags,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir
)

if enable_tests
  subdir('tests')
endif
