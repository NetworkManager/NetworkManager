# SPDX-License-Identifier: LGPL-2.1-or-later

project(
  'NetworkManager', 'c',
# NOTE: When incrementing version also add corresponding
#       NM_VERSION_x_y_z macros in
#       "src/libnm-core-public/nm-version-macros.h.in"
  version: '1.57.3-dev',
  license: 'GPL2+',
  default_options: [
    'buildtype=debugoptimized',
    'c_std=gnu11',
    'warning_level=2' # value "2" will add "-Wall" and "-Wextra" to the compiler flags
  ],
  meson_version: '>= 0.56.0',
)

nm_name = meson.project_name()
nm_version = meson.project_version()

version_and_suffix = nm_version.split('-')
version_array = version_and_suffix[0].split('.')
if version_and_suffix.length() == 2
  version_suffix = version_and_suffix[1]
else
  assert(version_and_suffix.length() == 1)
  version_suffix = ''
endif

# In the C API we encode the version in 90+ scheme (1.56-rc1 = 1.55.90, rc2 = .91, etc)
if version_suffix == '' or version_suffix == 'dev'
  assert(version_array.length() == 3)
  nm_major_version = version_array[0].to_int()
  nm_minor_version = version_array[1].to_int()
  nm_micro_version = version_array[2].to_int()
elif version_suffix.startswith('rc')
  assert(version_array.length() == 2)
  nm_major_version = version_array[0].to_int()
  nm_minor_version = version_array[1].to_int() - 1
  nm_micro_version = version_suffix.substring(2).to_int() + 89
else
  error('Invalid suffix: ' + version_suffix)
endif

if nm_minor_version % 2 == 1 and version_suffix == ''
  error('Expected a "-dev" or "-rc" suffix')
elif nm_minor_version %2 == 0 and version_suffix != ''
  error('Unexpected "' + version_suffix + '" suffix')
endif

nm_id_prefix = 'NM'

nm_gir_version = '1.0'

# Distribution version string
dist_version = get_option('dist_version')
if dist_version == ''
  dist_version = nm_version
endif

nm_prefix = get_option('prefix')
nm_bindir = join_paths(nm_prefix, get_option('bindir'))
nm_datadir = join_paths(nm_prefix, get_option('datadir'))
nm_includedir = join_paths(nm_prefix, get_option('includedir'))
nm_libdir = join_paths(nm_prefix, get_option('libdir'))
nm_libexecdir = join_paths(nm_prefix, get_option('libexecdir'))
nm_localedir = join_paths(nm_prefix, get_option('localedir'))
nm_localstatedir = join_paths(nm_prefix, get_option('localstatedir'))
nm_mandir = join_paths(nm_prefix, get_option('mandir'))
nm_sbindir = join_paths(nm_prefix, get_option('sbindir'))
nm_sysconfdir = join_paths(nm_prefix, get_option('sysconfdir'))

nm_runstatedir = get_option('runtime_dir')
if nm_runstatedir == ''
  if get_option('prefix') == '/usr'
    nm_runstatedir = '/run'
  else
    nm_runstatedir = join_paths(nm_localstatedir, 'run')
  endif
endif

nm_pkgsbindir = join_paths(nm_sbindir, nm_name)
nm_pkgconfdir = join_paths(nm_sysconfdir, nm_name)
nm_pkgdatadir = join_paths(nm_datadir, nm_name)
nm_pkgincludedir = join_paths(nm_includedir, nm_name)
nm_pkglibdir = join_paths(nm_prefix, 'lib', nm_name)
nm_pkgrundir = join_paths(nm_runstatedir, nm_name)
nm_pkgstatedir = join_paths(nm_localstatedir, 'lib', nm_name)
nm_vpndir = join_paths(nm_libdir, nm_name)
nm_plugindir = join_paths(nm_libdir, nm_name, dist_version)

introspection_extra_cflags = [
  '-Wno-incompatible-pointer-types-discards-qualifiers',
]

libnm_name = 'libnm'

current = 1
revision = 0
age = 1
libnm_version = '@0@.@1@.@2@'.format(current - age, age, revision)

libnm_pkgincludedir = join_paths(nm_includedir, libnm_name)

fs = import('fs')
gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

source_root = meson.current_source_dir()
build_root = meson.current_build_dir()

po_dir = source_root / 'po'

top_inc = include_directories('.')

perl = find_program('perl')

check_exports = find_program(join_paths(source_root, 'tools', 'check-exports.sh'))

cc = meson.get_compiler('c')

config_h = configuration_data()

# defines
set_defines = [
  ['GETTEXT_PACKAGE', nm_name],
  ['PACKAGE_STRING', '@0@ @1@'.format(nm_name, nm_version)],
  ['VERSION', nm_version],
]

default_test_timeout = 180

foreach define: set_defines
  config_h.set_quoted(define[0], define[1])
endforeach

# headers
config_h.set10('HAVE_SYS_AUXV_H', cc.has_header('sys/auxv.h'))
config_h.set10('HAVE_THREADS_H', cc.has_header('threads.h'))

use_sys_random = cc.has_function('getrandom', prefix: '#include <sys/random.h>')
config_h.set10('USE_SYS_RANDOM_H', use_sys_random)
config_h.set10('HAVE_GETRANDOM', use_sys_random or cc.has_function('getrandom', prefix: '#include <linux/random.h>'))

config_h.set10('HAVE_PIDFD_OPEN', cc.has_function('pidfd_open', prefix: '''#include <stdlib.h>
                                                                           #include <unistd.h>
                                                                           #include <signal.h>
                                                                           #include <sys/wait.h>'''))
config_h.set10('HAVE_PIDFD_SEND_SIGNAL', cc.has_function('pidfd_send_signal', prefix: '''#include <stdlib.h>
                                                                                         #include <unistd.h>
                                                                                         #include <signal.h>
                                                                                         #include <sys/wait.h>'''))
config_h.set10('HAVE_RT_SIGQUEUEINFO', cc.has_function('rt_sigqueueinfo', prefix: '''#include <stdlib.h>
                                                                                     #include <unistd.h>
                                                                                     #include <signal.h>
                                                                                     #include <sys/wait.h>'''))
config_h.set('HAVE_SECURE_GETENV', cc.has_function('secure_getenv'))
config_h.set('HAVE___SECURE_GETENV', cc.has_function('__secure_getenv'))
config_h.set10('HAVE_DECL_REALLOCARRAY', cc.has_function('reallocarray', prefix: '''#include <malloc.h>
                                                                                    #include <stdlib.h>'''))
config_h.set10('HAVE_DECL_EXPLICIT_BZERO', cc.has_function('explicit_bzero', prefix: '#include <string.h>'))
config_h.set10('HAVE_DECL_MEMFD_CREATE', cc.has_function('memfd_create', prefix: '#include <sys/mman.h>'))

config_h.set10('HAVE_DLVSYM', cc.has_function('dlvsym', prefix: '''#define _GNU_SOURCE
                                                                   #include <dlfcn.h>'''))

# types
config_h.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
config_h.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
config_h.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))
config_h.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
config_h.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
config_h.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
config_h.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))

# compiler flags
common_flags = []
common_ldflags = []

enable_ld_gc = get_option('ld_gc')
if enable_ld_gc
  test_c_flags = [
    '-fdata-sections',
    '-ffunction-sections',
  ]

  test_ldflags = ['-Wl,--gc-sections']

  foreach cflag: test_c_flags
    assert(cc.has_argument(cflag), 'Unused symbol eviction requested but not supported. Use -Dld_gc=false to build without it.')
  endforeach

  foreach ldflag: test_ldflags
    assert(cc.has_link_argument(ldflag), 'Linker garbage collection requested but not supported. Use -Dld_gc=false to build without it.')
  endforeach

  common_flags += test_c_flags
  common_ldflags += test_ldflags
endif

enable_lto = get_option('b_lto')
if enable_lto
  cc_version = cc.version()
  if cc.get_id() == 'clang'
    if cc_version <= '18.0.0'
      error('Clang version should be greater than 18.0.0, got : ' + cc_version)
    endif
  elif cc_version < '12.0'
    # GCC < 12 breaks libnm symbol versioning with LTO, use workarounds
    lto_flag = '-flto-partition=none'
    assert(cc.has_argument(lto_flag), '-flto-partition=none not supported. Disable link-time optimization with -Db_lto=false.')
    common_flags += lto_flag
    common_ldflags += lto_flag
  endif
endif

common_flags += cc.get_supported_arguments([
  '-Wcast-align=strict',
  '-Wdeclaration-after-statement',
  '-Wfloat-equal',
  '-Wformat-nonliteral',
  '-Wformat-security',
  '-Wimplicit-function-declaration',
  '-Wimplicit-int',
  '-Winit-self',
  '-Wint-conversion',
  '-Wlogical-op',
  '-Wmissing-declarations',
  '-Wmissing-include-dirs',
  '-Wmissing-prototypes',
  '-Wold-style-definition',
  '-Wparentheses-equality',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wshift-negative-value',
  '-Wstrict-prototypes',
  '-Wtypedef-redefinition',
  '-Wundef',
  '-Wunknown-attributes',
  '-Wvla',
  '-Wno-duplicate-decl-specifier',
  '-Wno-format-truncation',
  '-Wno-format-y2k',
  '-Wno-gnu-variable-sized-type-not-at-end',
  '-Wno-missing-field-initializers',
  '-Wno-pragmas',
  '-Wno-sign-compare',
  '-Wno-tautological-constant-out-of-range-compare',
  '-Wno-unknown-pragmas',
  '-Wno-unused-parameter',
  '-fno-strict-aliasing',
])

if cc.has_argument('-Wimplicit-fallthrough')
  if cc.compiles('''
                 int main(int argc, char **argv) {
                     int r = 0;
                     switch (argc) {
                     case 0:
                         r++;
                         /* fall-through */
                     case 1:
                         r++;
                         break;
                     }
                     return r;
                 }
                 ''',
                 args: '-Werror=implicit-fallthrough',
                 name: '-Werror=implicit-fallthrough')
    common_flags += '-Wimplicit-fallthrough'
  endif
endif

add_project_arguments(common_flags, language: 'c')
add_project_link_arguments(common_ldflags, language: 'c')

linker_script_binary   = join_paths(source_root, 'linker-script-binary.ver')
linker_script_devices  = join_paths(source_root, 'linker-script-devices.ver')
linker_script_settings = join_paths(source_root, 'linker-script-settings.ver')

ldflags_linker_script_binary   = [ '-Wl,--version-script,@0@'.format(linker_script_binary) ]
ldflags_linker_script_devices  = [ '-Wl,--version-script,@0@'.format(linker_script_devices) ]
ldflags_linker_script_settings = [ '-Wl,--version-script,@0@'.format(linker_script_settings) ]

uuid_dep = dependency('uuid')
libelogind_dep = dependency('libelogind', version: '>= 219', required: false)
libudev_dep = dependency('libudev', version: '>= 175')
dbus_dep = dependency('dbus-1', version: '>= 1.1')
libndp_dep = dependency('libndp')

jansson_dep = dependency('jansson', version: '>= 2.7', required: false)
config_h.set10('WITH_JANSSON', jansson_dep.found())

jansson_msg = 'no'
if jansson_dep.found()
  jansson_libdir = jansson_dep.get_variable(pkgconfig: 'libdir')
  res = run_command(find_program('eu-readelf', 'readelf'), '-d', join_paths(jansson_libdir, 'libjansson.so'), check: false)
  jansson_soname = ''
  foreach line: res.stdout().split('\n')
    if line.strip().contains('SONAME')
       jansson_soname = line.split('[')[1].split(']')[0]
    endif
  endforeach
  assert(jansson_soname != '', 'Unable to determine Jansson SONAME')
  config_h.set_quoted('JANSSON_SONAME', jansson_soname)
  jansson_msg = 'yes (soname: ' + jansson_soname + ')'
endif

libsystemd_dep = dependency('libsystemd', version: '>= 209', required: false)
libsystemd_login_dep = dependency('libsystemd-login', version: '>= 183', required: false)

config_h.set10('HAVE_LIBSYSTEMD', libsystemd_dep.found())

systemd_dep = dependency('systemd', required: false)

gio_unix_dep = dependency('gio-unix-2.0', version: '>= 2.42')

glib_dep = declare_dependency(
  dependencies: [
    gio_unix_dep,
    dependency('gmodule-2.0'),
  ],
  compile_args: [
    '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_42',
    '-DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_42',
  ]
)

enable_ifcfg_rh = get_option('ifcfg_rh')

config_migrate_ifcfg_rh_default = get_option('config_migrate_ifcfg_rh_default').to_string()
if config_migrate_ifcfg_rh_default == 'true'
  assert(enable_ifcfg_rh, 'ifcfg-rh migration can be enabled by default only when the ifcfg-rh plugin is enabled')
endif
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_MIGRATE_IFCFG_RH', config_migrate_ifcfg_rh_default)

enable_ifupdown = get_option('ifupdown')
if enable_ifupdown == 'auto'
  enable_ifupdown = (run_command('test', '-e', '/etc/debian_version', check: false).returncode() == 0)
else
  enable_ifupdown = (enable_ifupdown != 'false')
endif

config_plugins_default = get_option('config_plugins_default')
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_PLUGINS', config_plugins_default)

config_h.set10('WITH_CONFIG_PLUGIN_IFCFG_RH', enable_ifcfg_rh)
config_h.set10('WITH_CONFIG_PLUGIN_IFUPDOWN', enable_ifupdown)

config_h.set_quoted('NM_DIST_VERSION', dist_version)

enable_wifi = get_option('wifi')
config_h.set10('WITH_WIFI', enable_wifi)

enable_iwd = get_option('iwd')
assert((not enable_iwd) or enable_wifi, 'Enabling iwd support requires Wi-Fi support as well')
config_h.set10('WITH_IWD', enable_iwd)

wext = get_option('wext')
if wext == 'true'
  error('Wireless Extensions support is deprecated and will be removed in the future. Use -Dwext=force to keep using it')
endif
enable_wext = (wext == 'force')
config_h.set10('HAVE_WEXT', enable_wext)

# Checks for libdl - on certain platforms its part of libc
dl_dep = cc.find_library('dl')
'''
dl_deps = []

dl_dep = cc.find_library('dl')
if dl_dep.found() and cc.has_function('dlopen')
  dl_deps += dl_dep
else
  dl_dep = dependency('dl', required: false)
  if dl_dep.found() and cc.has_function('dlopen', dependencies: dl_dep)
    dl_deps += dl_dep
  else
    dld_dep = dependency('dld', required: false)
    if dld_dep.found() and cc.has_function('dlopen', dependencies: dld_dep)
      dl_deps += dld_dep
    endif
  endif
endif
'''

# introspection support
enable_introspection = get_option('introspection')
if enable_introspection
  gir_dep = dependency('gobject-introspection-1.0', version: '>= 0.9.6', required: false)
  assert(gir_dep.found(), 'introspection support was requested, but the gobject-introspection library is not available. Use -Dintrospection=false to build without it.')
endif

udev_udevdir = get_option('udev_dir')
if udev_udevdir == 'no'
  install_udevdir = false
else
  install_udevdir = true
  if (udev_udevdir == '' or udev_udevdir == 'yes')
    udev_udevdir = join_paths(nm_prefix, 'lib/udev')
  endif
  assert(udev_udevdir.startswith('/'), 'udev_dir must be an absolute path, but is ' + udev_udevdir)
endif

systemd_systemdsystemunitdir = get_option('systemdsystemunitdir')
install_systemdunitdir = (systemd_systemdsystemunitdir != 'no')

if install_systemdunitdir and systemd_systemdsystemunitdir == ''
  assert(systemd_dep.found(), 'systemd required but not found, please provide a valid systemd user unit dir or disable it')
  systemd_systemdsystemunitdir = systemd_dep.get_variable(pkgconfig: 'systemdsystemunitdir', pkgconfig_define: ['rootprefix', nm_prefix])
endif

systemd_systemdsystemgeneratordir = get_option('systemdsystemgeneratordir')
install_systemdgeneratordir = (systemd_systemdsystemgeneratordir != 'no')

if install_systemdgeneratordir and systemd_systemdsystemgeneratordir == ''
  assert(systemd_dep.found(), 'systemd required but not found, please provide a valid systemd user generator dir or disable it')
  systemd_systemdsystemgeneratordir = systemd_dep.get_variable(pkgconfig: 'systemdsystemgeneratordir', pkgconfig_define: ['rootprefix', nm_prefix])
endif

enable_systemd_journal = get_option('systemd_journal')
if enable_systemd_journal
  assert(libsystemd_dep.found(), 'Missing systemd-journald support')
endif
config_h.set10('SYSTEMD_JOURNAL', enable_systemd_journal)

config_logging_backend_default = get_option('config_logging_backend_default')
if config_logging_backend_default == 'default'
  config_logging_backend_default = (enable_systemd_journal ? 'journal' : 'syslog')
endif
config_h.set_quoted('NM_CONFIG_DEFAULT_LOGGING_BACKEND', config_logging_backend_default)

config_wifi_backend_default = get_option('config_wifi_backend_default')
if config_wifi_backend_default == 'default'
  config_wifi_backend_default = 'wpa_supplicant'
elif config_wifi_backend_default == 'iwd'
  assert(enable_iwd, 'Setting the default Wi-Fi backend to iwd requires iwd support.')
endif
config_h.set_quoted('NM_CONFIG_DEFAULT_WIFI_BACKEND', config_wifi_backend_default)

session_tracking = get_option('session_tracking')
session_trackers = []

if session_tracking == 'systemd'
  logind_dep = libsystemd_dep
  if not logind_dep.found()
    logind_dep = dependency('libsystemd-login', required: false)
    assert(logind_dep.found(), 'You must have libsystemd or libsystemd-login installed to build with systemd-logind support')
  endif
  session_trackers += 'systemd-logind'
  config_h.set10('SESSION_TRACKING_SYSTEMD', true)
  config_h.set10('SESSION_TRACKING_ELOGIND', false)
elif session_tracking == 'elogind'
  logind_dep = libelogind_dep
  assert(logind_dep.found() and libelogind_dep.version().version_compare('>= 229'), 'You must have libelogind installed to build with elogind support.')
  session_trackers += 'elogind'
  config_h.set10('SESSION_TRACKING_SYSTEMD', false)
  config_h.set10('SESSION_TRACKING_ELOGIND', true)
else
  config_h.set10('SESSION_TRACKING_SYSTEMD', false)
  config_h.set10('SESSION_TRACKING_ELOGIND', false)
  logind_dep = dependency('', required:false)
endif

session_tracking_consolekit = get_option('session_tracking_consolekit')
if session_tracking_consolekit
  session_trackers += 'consolekit'
endif
config_h.set10('SESSION_TRACKING_CONSOLEKIT', session_tracking_consolekit)

hostname_persist = get_option('hostname_persist')
config_h.set('HOSTNAME_PERSIST_SUSE', (hostname_persist == 'suse'))
config_h.set('HOSTNAME_PERSIST_GENTOO', (hostname_persist == 'gentoo'))
config_h.set('HOSTNAME_PERSIST_SLACKWARE', (hostname_persist == 'slackware'))

suspend_resume = get_option('suspend_resume')

if suspend_resume == 'auto'
  if libsystemd_dep.found() or libsystemd_login_dep.found()
    suspend_resume = 'systemd'
  elif libelogind_dep.found()
    suspend_resume = 'elogind'
  else
    suspend_resume = 'consolekit'
  endif
endif

if suspend_resume == 'systemd'
  if libsystemd_dep.found()
    system_inhibit_dep = libsystemd_dep
  elif libsystemd_login_dep.found()
    system_inhibit_dep = libsystemd_login_dep
  else
    error('Need libsystemd for suspend_resume=systemd')
  endif
  config_h.set('SUSPEND_RESUME_SYSTEMD', true)
elif suspend_resume == 'elogind'
  assert(libelogind_dep.found(), 'Need libelogind for suspend_resume=elogind')
  system_inhibit_dep = libelogind_dep
  config_h.set('SUSPEND_RESUME_ELOGIND', true)
elif suspend_resume == 'consolekit'
  config_h.set('SUSPEND_RESUME_CONSOLEKIT', true)
else
  error('bug')
endif

# SELinux support
enable_selinux = get_option('selinux')
if enable_selinux
  selinux_dep = dependency('libselinux', required: false)
  assert(selinux_dep.found(), 'You must have libselinux installed to build. Use -Dselinux=false to disable it')
endif
config_h.set10('HAVE_SELINUX', enable_selinux)

# CLAT support
enable_clat = get_option('clat')
if enable_clat
  libbpf = dependency('libbpf', version: '>= 1.3.0', required: false)
  assert(libbpf.found(), 'You must have libbpf >= 1.3.0 installed to build. Use -Dclat=false to disable use of it')
  libndp_dep = dependency('libndp', version: '>= 1.9', required: false)
  assert(libndp_dep.found(), 'You must have libndp >= 1.9 installed to build with CLAT support. Use -Dclat=false to disable it')
endif
config_h.set10('HAVE_CLAT', enable_clat)

# libaudit support
libaudit = get_option('libaudit')
enable_libaudit = libaudit.contains('yes')
if enable_libaudit
  libaudit_dep = dependency('audit', required: false)
  assert(libaudit_dep.found(), 'You must have libaudit installed to build. Use -Dlibaudit=no to disable it')
endif
config_default_logging_audit = (libaudit == 'yes').to_string()
config_h.set_quoted('NM_CONFIG_DEFAULT_LOGGING_AUDIT', config_default_logging_audit)
config_h.set10('HAVE_LIBAUDIT', enable_libaudit)

# Teamd control checks
enable_teamdctl = get_option('teamdctl')
if enable_teamdctl
  assert(jansson_dep.found(), 'You must have jansson installed to build. Use -Dteamdctl=false to disable it')
  libteamdctl_dep = dependency('libteamdctl', version: '>= 1.9')
  assert(libteamdctl_dep.found(), 'You must have libteamdctl installed to build. Use -Dteamdctl=false to disable it')
endif
config_h.set10('WITH_TEAMDCTL', enable_teamdctl)

# polkit
enable_polkit = get_option('polkit')
if enable_polkit
  # FIXME: policydir should be relative to `datadir`, not `prefix`. Fixed in https://gitlab.freedesktop.org/polkit/polkit/merge_requests/2
  polkit_policydir = dependency('polkit-gobject-1').get_variable(pkgconfig: 'policydir', pkgconfig_define: ['prefix', nm_prefix])
  polkit_rulesdir = join_paths(fs.parent(polkit_policydir), 'rules.d')
endif

config_auth_polkit_default = get_option('config_auth_polkit_default')
if config_auth_polkit_default == 'default'
  config_auth_polkit_default = (enable_polkit ? 'true' : 'false')
endif
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT', config_auth_polkit_default)

enable_modify_system = get_option('modify_system')
if enable_modify_system
  # FIXME: remove this after everyone has stopped using modify_system
  error('modify_system=true is no longer allowed due to security reasons')
endif

polkit_noauth_group = get_option('polkit_noauth_group')

polkit_agent_helper_1_path = get_option('polkit_agent_helper_1')
foreach p : [ '/usr/libexec/polkit-agent-helper-1',
              '/usr/lib/polkit-1/polkit-agent-helper-1',
              '/usr/lib/policykit-1/polkit-agent-helper-1' ]
  if polkit_agent_helper_1_path == '' and run_command('test', '-f', p, check: false).returncode() == 0
    polkit_agent_helper_1_path = p
  endif
endforeach
if polkit_agent_helper_1_path == ''
  polkit_agent_helper_1_path = '/usr/lib/polkit-1/polkit-agent-helper-1'
endif
if polkit_agent_helper_1_path[0] != '/'
  error('polkit_agent_helper_1 must be an absolute path, but is ' + polkit_agent_helper_1_path)
endif
config_h.set_quoted('POLKIT_AGENT_HELPER_1_PATH', polkit_agent_helper_1_path)

crypto_nss_dep = dependency(
  'nss',
  required: false,
)
crypto_gnutls_dep = dependency(
  'gnutls',
  version: '>= 2.12',
  required: false,
)
crypto = get_option('crypto')
if crypto == 'nss'
    assert(crypto_nss_dep.found(), 'Requires nss crypto support')
    crypto_dep = crypto_nss_dep
elif crypto == 'gnutls'
    assert(crypto_gnutls_dep.found(), 'Requires gnutls crypto support')
    crypto_dep = crypto_gnutls_dep
else
    assert(crypto == 'null', 'Unexpected setting "crypto=' + crypto + '"')
endif

dbus_conf_dir = get_option('dbus_conf_dir')
if dbus_conf_dir == ''
  assert(dbus_dep.found(), 'D-Bus required but not found, please provide a valid system bus config dir')
  dbus_conf_dir = join_paths(dbus_dep.get_variable(pkgconfig: 'datarootdir', pkgconfig_define: ['prefix', nm_prefix]), 'dbus-1', 'system.d')
endif

dbus_interfaces_dir = dbus_dep.get_variable(pkgconfig: 'interfaces_dir',  pkgconfig_define: ['datadir', nm_datadir])
dbus_system_bus_services_dir = dbus_dep.get_variable(pkgconfig: 'system_bus_services_dir', pkgconfig_define: ['datadir', nm_datadir])

enable_firewalld_zone = get_option('firewalld_zone')
config_h.set10('WITH_FIREWALLD_ZONE', enable_firewalld_zone)

# pppd
enable_ppp = get_option('ppp')
NM_PPP_VERSION_2_5_OR_NEWER = false
if enable_ppp
  pppd_dep = dependency('pppd', required: false)
  if (pppd_dep.found())
    pppd_version = pppd_dep.version()
    NM_PPP_VERSION_2_5_OR_NEWER = true
  else
    assert(cc.has_header('pppd/pppd.h'), 'couldn\'t find pppd.h. pppd development headers are required')
    pppd_version = '2.4.9'
  endif

  pppd_path = get_option('pppd')
  if pppd_path == ''
    pppd = find_program('pppd', '/sbin/pppd', '/usr/sbin/pppd', required: false)
    assert(pppd.found(), 'pppd required but not found, please provide a valid pppd path or use -Dppp=false to disable it')
    if meson.version().version_compare('>= 0.55')
      pppd_path = pppd.full_path()
    else
      pppd_path = pppd.path()
    endif
  endif

  config_h.set_quoted('PPPD_PATH', pppd_path)

  pppd_plugin_dir = get_option('pppd_plugin_dir')
  if pppd_plugin_dir == ''
    pppd_plugin_dir = join_paths(nm_libdir, 'pppd', pppd_version)
  endif
endif
config_h.set10('WITH_PPP', enable_ppp)
config_h.set10('NM_PPP_VERSION_2_5_OR_NEWER', NM_PPP_VERSION_2_5_OR_NEWER)

# ModemManager1 with libmm-glib
enable_modem_manager = get_option('modem_manager')
if enable_modem_manager
  mm_glib_dep = dependency('mm-glib', version: '>= 0.7.991')

  mobile_broadband_provider_info_database = get_option('mobile_broadband_provider_info_database')
  if mobile_broadband_provider_info_database == ''
    mobile_broadband_provider_info_database = dependency('mobile-broadband-provider-info').get_variable(pkgconfig: 'database')
  endif
  config_h.set_quoted('MOBILE_BROADBAND_PROVIDER_INFO_DATABASE', mobile_broadband_provider_info_database)
endif
config_h.set10('WITH_WWAN', enable_modem_manager)

# Bluez5 DUN support
enable_bluez5_dun = get_option('bluez5_dun')
if enable_bluez5_dun
  bluez5_dep = dependency('bluez', version: '>= 5', required: false)
  assert(bluez5_dep.found(), 'Bluez 5.x development headers are required')
else
  bluez5_dep = declare_dependency()
endif
config_h.set10('WITH_BLUEZ5_DUN', enable_bluez5_dun)

# OFONO
enable_ofono = get_option('ofono')
config_h.set10('WITH_OFONO', enable_ofono)

# DHCP client support
config_dhcp_default = get_option('config_dhcp_default')
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_DHCP', config_dhcp_default)
config_dhcp_clients_enabled = [ 'internal' ]
dhcp_summary = ''
foreach client : [ 'dhcpcd', 'dhclient' ]
  client_path = get_option(client)
  client_enable = (client_path != 'no')
  if client_enable
    if client_path == ''
      client_prog = find_program(client,
                                 '/sbin/' + client,
                                 '/usr/sbin/pppd/' + client,
                                 '/usr/local/sbin/' + client,
                                 required : false)
      if client_prog.found()
        if meson.version().version_compare('>= 0.55')
          client_path = client_prog.full_path()
        else
          client_path = client_prog.path()
        endif
      else
        client_path = '/usr/sbin/' + client
        message('@0@ not found, assume path @1@'.format(client, client_path))
      endif
    endif
    config_h.set_quoted(client.to_upper() + '_PATH', client_path)
  endif
  if config_dhcp_default == client and not client_enable
    error(client + ' has not been enabled. Please don\'t disable it or use another configuration option for main.dhcp setting')
  endif
  config_h.set10('WITH_' + client.to_upper(), client_enable)
  dhcp_summary += ('  ' + client + ': ' + client_enable.to_string())
  if (client_enable)
    dhcp_summary += (' ' + client_path)
    config_dhcp_clients_enabled += client
  endif
  if (client == 'dhclient')
    dhcp_summary += ' (deprecated)'
  endif
  dhcp_summary += '\n'
endforeach

# Open vSwitch integration
enable_ovs = get_option('ovs')
if enable_ovs
  assert(jansson_dep.found(), 'jansson is needed for Open vSwitch integration. Use -Dovs=false to disable it')
endif
config_h.set10('WITH_OPENVSWITCH', enable_ovs)

# DNS resolv.conf managers
config_dns_rc_manager_default = get_option('config_dns_rc_manager_default')
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_RC_MANAGER', config_dns_rc_manager_default)
resolv_conf_summary = ''
foreach prog_name : ['resolvconf', 'netconfig']
  prog_path = get_option(prog_name)
  prog_enable = (prog_path != 'no')

  if prog_enable
    if prog_path == ''
      prog = find_program(prog_name,
                          '/usr/' + prog_name,
                          '/usr/sbin/' + prog_name,
                          '/usr/local/sbin/' + prog_name,
                          required : false)
      if prog.found()
        if meson.version().version_compare('>= 0.55')
          prog_path = prog.full_path()
        else
          prog_path = prog.path()
        endif
      else
        prog_enable = false
      endif
    endif
  endif

  if prog_enable
    config_h.set_quoted(prog_name.to_upper() + '_PATH', prog_path)
  elif config_dns_rc_manager_default == prog_name
    error(prog_name + ' has not been enabled. Please don\'t disable it or use another configuration option for main.rc-manager setting')
  endif

  resolv_conf_summary += '  ' + prog_name + ': ' + prog_enable.to_string()
  if prog_enable
    resolv_conf_summary += ' ' + prog_path
  endif
  resolv_conf_summary += '\n'
endforeach

# external misc tools paths
default_paths = ['/sbin', '/usr/sbin']

# 0: cmdline option, 1: paths, 2: fallback
progs = [['iptables', default_paths, '/usr/sbin/iptables'],
         ['ip6tables', default_paths, '/usr/sbin/ip6tables'],
         ['nft',      default_paths, '/usr/sbin/nft'],
         ['dnsmasq',  default_paths, ''],
         ['modprobe', default_paths, '/sbin/modprobe']
        ]

foreach prog : progs
  path = get_option(prog[0])
  if path == ''
    search_paths = [ prog[0] ]
    foreach path : prog[1]
      search_paths += (path + '/' + prog[0])
    endforeach
    exe = find_program(search_paths, required : false)
    if meson.version().version_compare('>= 0.55')
      path = exe.found() ? exe.full_path() : prog[2]
    else
      path = exe.found() ? exe.path() : prog[2]
    endif
  endif
  name = prog[0].to_upper() + '_PATH'
  config_h.set_quoted(name, path)
endforeach

# system CA certificates path
system_ca_path = get_option('system_ca_path')
config_h.set_quoted('SYSTEM_CA_PATH', system_ca_path)

# kernel firmware dir
kernel_firmware_dir = get_option('kernel_firmware_dir')
config_h.set_quoted('KERNEL_FIRMWARE_DIR', kernel_firmware_dir)

enable_libpsl = get_option('libpsl')
if enable_libpsl
  libpsl_dep = dependency('libpsl', version: '>= 0.1')
endif
config_h.set10('WITH_LIBPSL', enable_libpsl)

libcurl_dep = dependency('libcurl', version: '>= 7.24.0', required: false)

enable_concheck = get_option('concheck')
if enable_concheck
  assert(libcurl_dep.found(), 'concheck requires libcurl library. Use -Dconcheck=false to disable it')
endif
config_h.set10('WITH_CONCHECK', enable_concheck)

config_h.set10('HAVE_READLINE_HISTORY', false)
config_h.set10('HAVE_EDITLINE_READLINE', false)
with_readline = get_option('readline')
if with_readline != 'none'
  if with_readline == 'libreadline' or with_readline == 'auto'
    readline = cc.find_library('readline', required: false)
    if readline.found()
      readline_dep = declare_dependency(link_args: '-lreadline')
      config_h.set10('HAVE_READLINE_HISTORY', true)
      with_readline = 'libreadline'
    else
      assert(with_readline == 'auto', 'libreadline was not found')
    endif
  endif
  if with_readline == 'libedit' or with_readline == 'auto'
    edit = dependency('libedit', required: false)
    if edit.found()
      readline_dep = declare_dependency(link_args: '-ledit')
      config_h.set10('HAVE_EDITLINE_READLINE', true)
      with_readline = 'libedit'
    else
      assert(with_readline == 'auto', 'libedit was not found')
      with_readline = 'none'
    endif
  endif
endif

enable_nmcli = get_option('nmcli')
if enable_nmcli
  assert(with_readline != 'none', 'nmcli requires readline library (-Dnmcli=false or -Dreadline=auto|libreadline|libedit|none)')
endif

enable_nmtui = get_option('nmtui')
if enable_nmtui
  newt_dep = dependency('libnewt', version: '>= 0.52.15', required: false)
  assert(newt_dep.found(), 'You must have libnewt installed to build nmtui. Use -Dnmtui=false to disable it')
endif

enable_nm_cloud_setup = get_option('nm_cloud_setup')
if enable_nm_cloud_setup
  assert(libcurl_dep.found(), 'nm-cloud-setup requires libcurl library. Use -Dnm_cloud_setup=false to disable it')
  assert(jansson_dep.found(), 'nm-cloud-setup requires jansson library. Use -Dnm_cloud_setup=false to disable it')
endif

enable_man = get_option('man')
enable_docs = get_option('docs')

more_asserts = get_option('more_asserts')
if more_asserts == 'auto'
  if nm_minor_version % 2 == 0
    more_asserts = 'no'
  else
    more_asserts = 'all'
  endif
endif
if more_asserts == 'no'
  more_asserts = 0
elif more_asserts == 'all'
  more_asserts = 100
else
  more_asserts = more_asserts.to_int()
endif
config_h.set('NM_MORE_ASSERTS', more_asserts)

more_logging = get_option('more_logging')
config_h.set10('NM_MORE_LOGGING', more_logging)

config_h.set10('_NM_CC_SUPPORT_GENERIC',
  cc.compiles(
    'int foo(void); static const char *const buf[1] = { "a" }; int foo() { int a = 0; int b = _Generic (a, int: 4) + _Generic(buf, const char *const*: 5); return b + a; }'
  )
)

config_h.set10('_NM_CC_SUPPORT_AUTO_TYPE',
  cc.compiles(
    'int main() { int a = 0; __auto_type b = a; return b + a; };'
  )
)

# Vala bindings
vapi_opt = get_option('vapi')
if vapi_opt == 'false'
  enable_vapi = false
else
  vala_req_version = '>= 0.17.1.24'
  enable_vapi = true

  if not enable_introspection
    assert(vapi_opt != 'true', 'vala api require GObject introspection. Use -Dvapi=false to disable it')
    enable_vapi = false
  endif

  if enable_vapi and not add_languages('vala', required: false)
    assert(vapi_opt != 'true', 'vala is required to build. Use -Dvapi=false to disable it')
    enable_vapi = false
  endif

  if enable_vapi and not meson.get_compiler('vala').version().version_compare(vala_req_version)
    assert(vapi_opt != 'true', 'vala ' + vala_req_version + ' is required to build. Use -Dvapi=false to disable it')
    enable_vapi = false
  endif
endif

test(
  'check-local-gitlab-ci',
  find_program(join_paths(source_root, 'tools', 'check-gitlab-ci.sh')),
  args: [source_root],
)

test(
  'check-tree',
  find_program(join_paths(source_root, 'tools', 'check-tree.sh')),
)

# Tests, utilities and documentation
tests = get_option('tests')
enable_tests = (tests != 'no')
require_root_tests = (tests == 'root')
test_script = find_program(join_paths(source_root, 'tools', 'run-nm-test.sh'))

# valgrind
locations = get_option('valgrind')
enable_valgrind = (locations != ['no'])
if enable_valgrind
  valgrind = find_program(locations, required: false)
  enable_valgrind = valgrind.found()
endif

if enable_valgrind
  valgrind_suppressions_path = get_option('valgrind_suppressions')
  if valgrind_suppressions_path == ''
    valgrind_suppressions_path = join_paths(source_root, 'valgrind.suppressions')
  endif
  if meson.version().version_compare('>= 0.55')
    valgrind_path = valgrind.full_path()
  else
    valgrind_path = valgrind.path()
  endif
endif

test_args = [
  '--called-from-make',
  build_root,
  enable_valgrind ? valgrind_path : '',
  enable_valgrind ? valgrind_suppressions_path : '',
  '--launch-dbus=auto',
]

python_mod = import('python')
python = python_mod.find_installation('python3', required: false)

if python.found()
  if meson.version().version_compare('>= 0.55')
    python_path = python.full_path()
  else
    python_path = python.path()
  endif
  config_h.set_quoted('TEST_NM_PYTHON', python_path)
endif

# libnvme (NBFT support)
enable_nbft = get_option('nbft')
if enable_nbft
  libnvme_dep = dependency('libnvme', version: '>= 1.5', required: false)
  assert(libnvme_dep.found(), 'NBFT support was requested, but the libnvme library is not available. Use -Dnbft=false to build without it.')
endif
config_h.set10('WITH_NBFT', enable_nbft)

data_conf = configuration_data()
data_conf.set('DISTRO_NETWORK_SERVICE',                  (enable_ifcfg_rh ? 'network.service' : ''))
data_conf.set('NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT',    config_default_logging_audit)
data_conf.set('NM_CONFIG_DEFAULT_LOGGING_BACKEND_TEXT',  config_logging_backend_default)
data_conf.set('NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_TEXT', config_auth_polkit_default)
data_conf.set('NM_CONFIG_DEFAULT_MAIN_DHCP',             config_dhcp_default)
data_conf.set('NM_CONFIG_DEFAULT_MAIN_RC_MANAGER',       config_dns_rc_manager_default)
data_conf.set('NM_CONFIG_DEFAULT_MAIN_MIGRATE_IFCFG_RH_TEXT', config_migrate_ifcfg_rh_default)
data_conf.set('NM_CONFIG_DEFAULT_WIFI_BACKEND_TEXT',     config_wifi_backend_default)
data_conf.set('NM_DHCP_CLIENTS_ENABLED',                 ', '.join(config_dhcp_clients_enabled))
data_conf.set('NM_MAJOR_VERSION',                        nm_major_version)
data_conf.set('NM_MICRO_VERSION',                        nm_micro_version)
data_conf.set('NM_MINOR_VERSION',                        nm_minor_version)
data_conf.set('NM_VERSION',                              nm_version)
data_conf.set('VERSION',                                 nm_version)
data_conf.set('bindir',                                  nm_bindir)
data_conf.set('libexecdir',                              nm_libexecdir)
data_conf.set('localstatedir',                           nm_localstatedir)
data_conf.set('nmrundir',                                nm_pkgrundir)
data_conf.set('nmstatedir',                              nm_pkgstatedir)
data_conf.set('sbindir',                                 nm_sbindir)
data_conf.set('sysconfdir',                              nm_sysconfdir)

content_files = []

subdir('introspection')
subdir('src')
subdir('data')
subdir('po')

if enable_vapi
  subdir('vapi')
endif

test(
  'check-vapi',
  find_program(join_paths(source_root, 'tools', 'check-vapi.sh')),
)

test(
  'check-nm-autoptr',
  find_program(join_paths(source_root, 'tools', 'check-nm-autoptr.sh')),
)

subdir('examples/C/glib')

enable_qt = get_option('qt')
if enable_qt != 'false'
  qt_core_dep = dependency('QtCore', version: '>= 4', required: enable_qt == 'yes')
  qt_dbus_dep = dependency('QtDBus', required: enable_qt == 'yes')
  qt_network_dep = dependency('QtNetwork', required: enable_qt == 'yes')

  # If enable_qt=='yes' we have all the dependencies. If it's 'auto', skip
  # building the Qt examples if any dependency is missing.
  if qt_core_dep.found() and qt_dbus_dep.found() and qt_network_dep.found()
    add_languages('cpp')
    subdir('examples/C/qt')
  endif
endif

# The man/ directory builds a couple targets needed by the docs build too.
# If we build with docs but no man, then enter the subdir and only build
# some targets.
if enable_docs or enable_man
  subdir('man')
endif
if enable_docs
  assert(enable_introspection, '-Ddocs=true requires -Dintrospection=true')
  subdir('docs')
  meson.add_dist_script(
    'tools/meson-dist-data.sh',
    '--build-root', build_root
  )
endif

configure_file(
  input: 'config.h.meson',
  output: '@BASENAME@',
  configuration: config_h,
)

config_extra_h = configuration_data()

config_extra_h.set_quoted('BINDIR',            nm_bindir)
config_extra_h.set_quoted('DATADIR',           nm_datadir)
config_extra_h.set_quoted('LIBEXECDIR',        nm_libexecdir)
config_extra_h.set_quoted('LOCALSTATEDIR',     nm_localstatedir)
config_extra_h.set_quoted('NMCONFDIR',         nm_pkgconfdir)
config_extra_h.set_quoted('NMLIBDIR',          nm_pkglibdir)
config_extra_h.set_quoted('NMLOCALEDIR',       nm_localedir)
config_extra_h.set_quoted('NMPLUGINDIR',       nm_plugindir)
config_extra_h.set_quoted('NMRUNDIR',          nm_pkgrundir)
config_extra_h.set_quoted('NMSTATEDIR',        nm_pkgstatedir)
config_extra_h.set_quoted('NMVPNDIR',          nm_vpndir)
config_extra_h.set_quoted('NM_BUILD_BUILDDIR', build_root)
config_extra_h.set_quoted('NM_BUILD_SRCDIR',   source_root)
if enable_ppp
    config_extra_h.set_quoted('PPPD_PLUGIN_DIR', pppd_plugin_dir)
endif
config_extra_h.set_quoted('PREFIX',            nm_prefix)
config_extra_h.set_quoted('RUNSTATEDIR',       nm_runstatedir)
config_extra_h.set_quoted('SYSCONFDIR',        nm_sysconfdir)

configure_file(
  input: 'config-extra.h.meson',
  output: '@BASENAME@',
  configuration: config_extra_h,
)

meson.add_install_script(
  join_paths('tools', 'meson-post-install.sh'),
  nm_datadir,
  nm_bindir,
  nm_pkgconfdir,
  nm_pkglibdir,
  nm_pkgstatedir,
  nm_mandir,
  nm_sysconfdir,
  enable_man ? '1' : '0',
  enable_ifcfg_rh ? '1' : '0',
  enable_nm_cloud_setup ? '1' : '0',
  install_systemdunitdir ? '1' : '0',
)

output = '\nSystem paths:\n'
output += '  prefix: ' + nm_prefix + '\n'
output += '  exec_prefix: ' + nm_prefix + '\n'
output += '  systemdunitdir: ' + systemd_systemdsystemunitdir + '\n'
output += '  systemdgeneratordir: ' + systemd_systemdsystemgeneratordir + '\n'
output += '  udev_dir: ' + udev_udevdir + '\n'
output += '  nmbinary: ' + nm_pkgsbindir + '\n'
output += '  nmconfdir: ' + nm_pkgconfdir + '\n'
output += '  nmlibdir: ' + nm_pkglibdir + '\n'
output += '  nmdatadir: ' + nm_pkgdatadir + '\n'
output += '  nmstatedir: ' + nm_pkgstatedir + '\n'
output += '  nmrundir: ' + nm_pkgrundir + '\n'
output += '  nmvpndir: ' + nm_vpndir + '\n'
output += '  nmplugindir: ' + nm_plugindir + '\n'
output += '  system_ca_path: ' + system_ca_path + '\n'
output += '  dbus_conf_dir: ' + dbus_conf_dir + '\n'
output += '\nPlatform:\n'
output += '  session tracking: ' + ','.join(session_trackers) + '\n'
output += '  suspend/resume: ' + suspend_resume + '\n'
output += '  policykit: ' + enable_polkit.to_string() + ' (default: ' + config_auth_polkit_default + ', noauth_group: "' + polkit_noauth_group + '")\n'
output += '  polkit-agent-helper-1: ' + polkit_agent_helper_1_path + '\n'
output += '  selinux: ' + enable_selinux.to_string() + '\n'
output += '  systemd-journald: ' + enable_systemd_journal.to_string() + ' (default: logging.backend=' + config_logging_backend_default + ')\n'
output += '  hostname persist: ' + hostname_persist + '\n'
output += '  libaudit: ' + enable_libaudit.to_string() + ' (default: logging.audit=' + config_default_logging_audit + ')\n'
output += '\nFeatures:\n'
output += '  wext: ' + enable_wext.to_string() + '\n'
output += '  wifi: ' + enable_wifi.to_string() + '\n'
output += '  iwd:  ' + enable_iwd.to_string() + '\n'
output += '  pppd: ' + enable_ppp.to_string()
if enable_ppp
  output += ' ' + pppd_path + ' plugins:' + pppd_plugin_dir
endif
output += '\n'
output += '  jansson: ' + jansson_msg + '\n'
output += '  iptables: ' + config_h.get('IPTABLES_PATH') + '\n'
output += '  ip6tables: ' + config_h.get('IP6TABLES_PATH') + '\n'
output += '  nft: ' + config_h.get('NFT_PATH') + '\n'
output += '  modprobe: ' + config_h.get('MODPROBE_PATH') + '\n'
output += '  modemmanager-1: ' + enable_modem_manager.to_string() + '\n'
if enable_modem_manager
  output += '  mobile-broadband-provider-info-database: ' + mobile_broadband_provider_info_database + '\n'
endif
output += '  ofono: ' + enable_ofono.to_string() + '\n'
output += '  concheck: ' + enable_concheck.to_string() + '\n'
output += '  libteamdctl: ' + enable_teamdctl.to_string() + '\n'
output += '  ovs: ' + enable_ovs.to_string() + '\n'
output += '  clat: ' + enable_clat.to_string() + '\n'
output += '  nmcli: ' + enable_nmcli.to_string() + '\n'
output += '  nmtui: ' + enable_nmtui.to_string() + '\n'
output += '  nm-cloud-setup: ' + enable_nm_cloud_setup.to_string() + '\n'
output += '\nConfiguration_plugins (main.plugins=' + config_plugins_default + ')\n'
output += '  ifcfg-rh: ' + enable_ifcfg_rh.to_string() + ' (deprecated)\n'
output += '    default value of main.migrate-ifcfg-rh: ' +  config_migrate_ifcfg_rh_default + '\n'
output += '  ifupdown: ' + enable_ifupdown.to_string() + '\n'
output += '\nHandlers for /etc/resolv.conf:\n' + resolv_conf_summary
output += '\n'
output += '  config-dns-rc-manager-default: ' + config_dns_rc_manager_default + '\n'
output += '\nDHCP clients (default ' + config_dhcp_default + '):\n' + dhcp_summary
output += '\n'
output += '\nMiscellaneous:\n'
output += '  have introspection: ' + enable_introspection.to_string() + '\n'
output += '  build documentation and manpages: ' + enable_docs.to_string() + '\n'
output += '  firewalld zone for shared mode: ' + enable_firewalld_zone.to_string() + '\n'
# FIXME
#output += '  install pregenerated documentation and manpages: no
output += '  tests: ' + tests + '\n'
output += '  more-asserts: @0@\n'.format(more_asserts)
output += '  more-logging: ' + more_logging.to_string() + '\n'
output += '  warning-level: ' + get_option('warning_level') + '\n'
output += '  valgrind: ' + enable_valgrind.to_string()
if enable_valgrind
  output += ' ' + valgrind_path
endif
output += '\n'
output += '  code coverage: ' + get_option('b_coverage').to_string() + '\n'
output += '  LTO: ' + enable_lto.to_string() + '\n'
output += '  Linker garbage collection: ' + enable_ld_gc.to_string() + '\n'
output += '  crypto: ' + crypto + ' ('
output +=      'have-gnutls: ' + crypto_gnutls_dep.found().to_string() + ', '
output +=      'have-nss: ' + crypto_nss_dep.found().to_string() + ')\n'
output += '  sanitizers: ' + get_option('b_sanitize') + '\n'
output += '  Mozilla Public Suffix List: ' + enable_libpsl.to_string() + '\n'
output += '  vapi: ' + enable_vapi.to_string() + '\n'
output += '  readline: ' + with_readline + '\n'
message(output)
