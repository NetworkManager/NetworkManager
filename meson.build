project(
  'NetworkManager', 'c',
  version: '1.11.1',
  license: 'GPL2+',
  default_options: [
    'buildtype=debugoptimized',
    'c_std=gnu99'
  ],
  meson_version: '>= 0.44.0'
)

nm_name = meson.project_name()

nm_version = meson.project_version()
version_array = nm_version.split('.')
nm_major_version = version_array[0].to_int()
nm_minor_version = version_array[1].to_int()
nm_micro_version = version_array[2].to_int()

nm_id_prefix = 'NM'

nm_gir_version = '1.0'

nm_prefix = get_option('prefix')
nm_bindir = join_paths(nm_prefix, get_option('bindir'))
nm_datadir = join_paths(nm_prefix, get_option('datadir'))
nm_includedir = join_paths(nm_prefix, get_option('includedir'))
nm_libdir = join_paths(nm_prefix, get_option('libdir'))
nm_libexecdir = join_paths(nm_prefix, get_option('libexecdir'))
nm_localedir = join_paths(nm_prefix, get_option('localedir'))
nm_localstatedir = join_paths(nm_prefix, get_option('localstatedir'))
nm_mandir = join_paths(nm_prefix, get_option('mandir'))
nm_runstatedir = join_paths(nm_localstatedir, 'run')
nm_sbindir = join_paths(nm_prefix, get_option('sbindir'))
nm_sysconfdir = join_paths(nm_prefix, get_option('sysconfdir'))

nm_pkgsbindir = join_paths(nm_sbindir, nm_name)
nm_pkgconfdir = join_paths(nm_sysconfdir, nm_name)
nm_pkgdatadir = join_paths(nm_datadir, nm_name)
nm_pkgincludedir = join_paths(nm_includedir, nm_name)
nm_pkglibdir = join_paths(nm_libdir, nm_name)
nm_pkgrundir = join_paths(nm_runstatedir, nm_name)
nm_pkgstatedir = join_paths(nm_localstatedir, nm_name)

current = 1
revision = 0
age = 1
libnm_version = '@0@.@1@.@2@'.format(current - age, age, revision)

libnm_pkgincludedir = join_paths(nm_includedir, 'libnm')

current = 9
revision = 0
age = 7
libnm_util_version = '@0@.@1@.@2@'.format(current - age, age, revision)

current = 13
revision = 0
age = 9
libnm_glib_version = '@0@.@1@.@2@'.format(current - age, age, revision)

libnm_glib_pkgincludedir = join_paths(nm_includedir, 'libnm-glib')

current = 3
revision = 0
age = 2
libnm_glib_vpn_version = '@0@.@1@.@2@'.format(current - age, age, revision)

nm_debug = get_option('buildtype').contains('debug')

cc = meson.get_compiler('c')

config_h = configuration_data()

# defines
set_defines = [
  ['GETTEXT_PACKAGE', nm_name],
  ['PACKAGE_STRING', '@0@ @1@'.format(nm_name, nm_version)],
  ['VERSION', nm_version]
]

foreach define: set_defines
  config_h.set_quoted(define[0], define[1])
endforeach

# headers
config_h.set10('HAVE_SYS_AUXV_H', cc.has_header('sys/auxv.h'))

use_sys_random = cc.has_function('getrandom', prefix: '#include<sys/random.h>')
config_h.set10('USE_SYS_RANDOM_H', use_sys_random)
config_h.set10('HAVE_GETRANDOM', use_sys_random or cc.has_function('getrandom', prefix: '#include<linux/random.h>'))

# functions
# FIXME secure_getenv check is not useful?
config_h.set('HAVE_SECURE_GETENV', cc.has_function('secure_getenv'))
config_h.set('HAVE___SECURE_GETENV', cc.has_function('__secure_getenv'))
config_h.set10('HAVE_DECL_EXPLICIT_BZERO', cc.has_function('explicit_bzero', prefix: '#include<string.h>'))

# types
config_h.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix: '#include<sys/types.h>'))
config_h.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix: '#include<sys/types.h>'))

if not cc.has_type('pid_t', prefix: '#include<sys/types.h>')
  config_h.set('pid_t', 'int')
endif

# compiler flags
common_flags = []
common_ldflags = []

enable_ld_gc = get_option('ld_gc')
if enable_ld_gc
  test_cflags = [
    '-fdata-sections',
    '-ffunction-sections',
  ]

  test_ldflags = ['-Wl,--gc-sections']

  foreach cflag: test_cflags + test_ldflags
    assert(cc.has_argument(cflag), 'Unused symbol eviction requested but not supported. Use -Dld_gc=false to build without it.')
  endforeach

  common_flags += test_cflags
  common_ldflags += test_ldflags
endif

if nm_debug
  test_cflags = [
    '-fno-strict-aliasing',
    '-Wdeclaration-after-statement',
    '-Wfloat-equal',
    '-Wimplicit-fallthrough',
    '-Winit-self',
    '-Wlogical-op',
    '-Wmissing-declarations',
    '-Wmissing-include-dirs',
    '-Wmissing-prototypes',
    '-Wno-duplicate-decl-specifier',
    '-Wno-format-truncation',
    '-Wno-missing-braces',
    '-Wno-missing-field-initializers',
    '-Wno-pragmas',
    '-Wno-sign-compare',
    '-Wno-unused-parameter',
    '-Wparentheses-equality',
    '-Wpointer-arith',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wtypedef-redefinition',
    '-Wundef',
    '-Wunknown-attributes'
  ]

  common_flags += cc.get_supported_arguments(test_cflags)
endif

add_project_arguments(common_flags, language: 'c')
add_project_link_arguments(common_ldflags, language: 'c')

ldflag = '-Wl,--version-script'
have_version_script = host_machine.system().contains('linux') and cc.has_argument(ldflag)

if have_version_script
  linker_script_binary = join_paths(meson.source_root(), 'linker-script-binary.ver')
  linker_script_devices = join_paths(meson.source_root(), 'linker-script-devices.ver')
  linker_script_settings = join_paths(meson.source_root(), 'linker-script-settings.ver')
endif

uuid_dep = dependency('uuid')
libelogind_dep = dependency('libelogind', version: '>= 219', required: false)
libudev_dep = dependency('libudev', version: '>= 175')
dbus_dep = dependency('dbus-1', version: '>= 1.1')
libndp_dep = dependency('libndp')

# libnl support for the linux platform
libnl_dep = dependency('libnl-3.0', version: '>= 3.2.8', required: false)

jansson_dep = dependency('jansson', required: false)
config_h.set10('WITH_JANSSON', jansson_dep.found())

libsystemd_dep = dependency('libsystemd', version: '>= 209', required: false)
config_h.set10('HAVE_LIBSYSTEMD', libsystemd_dep.found())

systemd_dep = dependency('systemd', required: false)
have_systemd_200 = systemd_dep.found() and systemd_dep.version().version_compare('>= 200')

gio_unix_dep = dependency('gio-unix-2.0', version: '>= 2.32')

log_driver = join_paths(meson.source_root(), 'build-aux', (gio_unix_dep.version().version_compare('>= 2.37.6') ? 'tap-driver.sh' : 'test-driver'))

# FIXME: same version? which version?
# GLIB_VERSION_MIN_REQUIRED should match the version above.
# GLIB_VERSION_MAX_ALLOWED should be set to the same version;
# nm-glib.h will cause it to be overridden for the functions
# we have compat versions of.
glib_dep = declare_dependency(
  dependencies: [
    gio_unix_dep,
    dependency('gmodule-2.0')
  ],
  compile_args: [
    '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32',
    '-DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32'
  ]
)

check_distro = join_paths(meson.source_root(), 'check-distro.py')

redhat_releases =  ['/etc/redhat-release', '/etc/fedora-release', '/etc/mandriva-release']
if run_command(check_distro, redhat_releases).returncode() == 0
  distro = 'redhat'
elif run_command(check_distro, '/etc/SuSE-release').returncode() == 0
  distro = 'suse'
elif run_command(check_distro, '/etc/debian_version').returncode() == 0
  distro = 'debian'
elif run_command(check_distro, '/etc/gentoo-release').returncode() == 0
  distro = 'gentoo'
else
  distro = 'unknown'
endif

enable_ifcfg_rh = get_option('ifcfg_rh') or (distro == 'redhat')
enable_ifupdown = get_option('ifupdown') or (distro == 'debian')

enable_config_plugin_ibft = get_option('config_plugin_ibft')
config_h.set10('WITH_SETTINGS_PLUGIN_IBFT', enable_config_plugin_ibft)

config_plugins_default = get_option('config_plugins_default')
if config_plugins_default == ''
  config_plugins = []

  if enable_ifcfg_rh
    config_plugins += ['ifcfg-rh']
  endif

  if enable_ifupdown
    config_plugins += ['ifupdown']
  endif

output += '\nHandlers for /etc/resolv.conf:\n'
output += '  resolvconf: ' + enable_resolvconf.to_string()
if enable_resolvconf
  output += ' ' + resolvconf.path()
endif
output += '\n'
output += '  netconfig: ' + enable_netconfig.to_string()
if enable_netconfig
  output += ' ' + netconfig.path()
endif
output += '\n'
output += '  config-dns-rc-manager-default: ' + config_dns_rc_manager_default + '\n'
output += '\nDHCP clients (default ' + config_dhcp_default + '):\n'
output += '  dhcpcanon: ' + enable_dhcpcanon.to_string()
if enable_dhcpcd
  output += ' ' + dhcpcanon.path()
endif
output += '\n'
output += '  dhclient: ' + enable_dhclient.to_string()
if enable_dhclient
  output += ' ' + dhclient.path()
endif
output += '\n'
output += '  dhcpcd: ' + enable_dhcpcd.to_string()
if enable_dhcpcd
  output += ' ' + dhcpcd.path()
endif
output += '\n'
output += '  dhcpcd-supports-ipv6: ' + enable_dhcpcd_supports_ipv6.to_string() + '\n'
output += '\nMiscellaneous:\n'
output += '  have introspection: ' + enable_introspection.to_string() + '\n'
output += '  build documentation and manpages: ' + enable_docs.to_string() + '\n'
# FIXME
#output += '  install pregenerated documentation and manpages: no
output += '  tests: ' + tests + '\n'
output += '  more-asserts: @0@\n'.format(more_asserts)
output += '  more-logging: ' + more_logging.to_string() + '\n'
output += '  warning-level: ' + get_option('warning_level') + '\n'
output += '  valgrind: ' + enable_valgrind.to_string()
if enable_valgrind
  output += ' ' + valgrind.path()
endif
output += '\n'
output += '  code coverage: ' + get_option('b_coverage').to_string() + '\n'
output += '  LTO: ' + get_option('b_lto').to_string() + '\n'
output += '  Linker garbage collection: ' + enable_ld_gc.to_string() + '\n'
output += '  JSON validation for libnm: ' + enable_json_validation.to_string () + '\n'
output += '  sanitizers: ' + get_option('b_sanitize') + '\n'
output += '  Mozilla Public Suffix List: ' + enable_libpsl.to_string() + '\n'
message(output)
