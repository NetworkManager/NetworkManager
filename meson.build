project(
  'NetworkManager', 'c',
# NOTE: When incrementing version also:
#  - add corresponding NM_VERSION_x_y_z macros in
#    "shared/nm-version-macros.h.in"
#  - update number in configure.ac
  version: '1.19.4',
  license: 'GPL2+',
  default_options: [
    'buildtype=debugoptimized',
    'c_std=gnu11',
  ],
  meson_version: '>= 0.44.0',
)

nm_name = meson.project_name()

nm_version = meson.project_version()
version_array = nm_version.split('.')
nm_major_version = version_array[0].to_int()
nm_minor_version = version_array[1].to_int()
nm_micro_version = version_array[2].to_int()

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
nm_runstatedir = join_paths(nm_localstatedir, 'run')
nm_sbindir = join_paths(nm_prefix, get_option('sbindir'))
nm_sysconfdir = join_paths(nm_prefix, get_option('sysconfdir'))

nm_pkgsbindir = join_paths(nm_sbindir, nm_name)
nm_pkgconfdir = join_paths(nm_sysconfdir, nm_name)
nm_pkgdatadir = join_paths(nm_datadir, nm_name)
nm_pkgincludedir = join_paths(nm_includedir, nm_name)
nm_pkglibdir = join_paths(nm_prefix, 'lib', nm_name)
nm_pkgrundir = join_paths(nm_runstatedir, nm_name)
nm_pkgstatedir = join_paths(nm_localstatedir, 'lib', nm_name)
nm_vpndir = join_paths(nm_libdir, nm_name)
nm_plugindir = join_paths(nm_libdir, nm_name, dist_version)

libnm_name = 'libnm'

current = 1
revision = 0
age = 1
libnm_version = '@0@.@1@.@2@'.format(current - age, age, revision)

libnm_pkgincludedir = join_paths(nm_includedir, libnm_name)

nm_debug = get_option('buildtype').contains('debug')

cc = meson.get_compiler('c')

config_h = configuration_data()

# defines
set_defines = [
  ['GETTEXT_PACKAGE', nm_name],
  ['PACKAGE_STRING', '@0@ @1@'.format(nm_name, nm_version)],
  ['VERSION', nm_version],
]

default_test_timeout = 90

foreach define: set_defines
  config_h.set_quoted(define[0], define[1])
endforeach

# headers
config_h.set10('HAVE_SYS_AUXV_H', cc.has_header('sys/auxv.h'))

use_sys_random = cc.has_function('getrandom', prefix: '#include <sys/random.h>')
config_h.set10('USE_SYS_RANDOM_H', use_sys_random)
config_h.set10('HAVE_GETRANDOM', use_sys_random or cc.has_function('getrandom', prefix: '#include <linux/random.h>'))

# functions
# FIXME secure_getenv check is not useful?
config_h.set('HAVE_SECURE_GETENV', cc.has_function('secure_getenv'))
config_h.set('HAVE___SECURE_GETENV', cc.has_function('__secure_getenv'))
config_h.set10('HAVE_DECL_REALLOCARRAY', cc.has_function('reallocarray', prefix: '#include <malloc.h>'))
config_h.set10('HAVE_DECL_EXPLICIT_BZERO', cc.has_function('explicit_bzero', prefix: '#include <string.h>'))
config_h.set10('HAVE_DECL_MEMFD_CREATE', cc.has_function('memfd_create', prefix: '#include <sys/mman.h>'))

# types
config_h.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix: '#include <sys/types.h>'))
config_h.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix: '#include <sys/types.h>'))
config_h.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix: '#include <sys/types.h>'))

if not cc.has_type('pid_t', prefix: '#include <sys/types.h>')
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

enable_lto = get_option('b_lto')
if enable_lto
  # meson already adds '-flto'
  lto_flag = '-flto-partition=none'
  assert(cc.has_argument(lto_flag), '-flto-partition=none not supported. Disable link-time optimization with -Db_lto=false.')
  common_flags += lto_flag
  common_ldflags += lto_flag
endif

if nm_debug
  common_flags += cc.get_supported_arguments([
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
    '-Wno-gnu-variable-sized-type-not-at-end',
    '-Wno-missing-field-initializers',
    '-Wno-pragmas',
    '-Wno-sign-compare',
    '-Wno-unknown-pragmas',
    '-Wno-unused-parameter',
    '-Wparentheses-equality',
    '-Wpointer-arith',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wtypedef-redefinition',
    '-Wundef',
    '-Wunknown-attributes',
    '-fno-strict-aliasing',
  ])
endif

add_project_arguments(common_flags, language: 'c')
add_project_link_arguments(common_ldflags, language: 'c')

linker_script_binary   = join_paths(meson.source_root(), 'linker-script-binary.ver')
linker_script_devices  = join_paths(meson.source_root(), 'linker-script-devices.ver')
linker_script_settings = join_paths(meson.source_root(), 'linker-script-settings.ver')

ldflags_linker_script_binary   = [ '-Wl,--version-script,@0@'.format(linker_script_binary) ]
ldflags_linker_script_devices  = [ '-Wl,--version-script,@0@'.format(linker_script_devices) ]
ldflags_linker_script_settings = [ '-Wl,--version-script,@0@'.format(linker_script_settings) ]

uuid_dep = dependency('uuid')
libelogind_dep = dependency('libelogind', version: '>= 219', required: false)
libudev_dep = dependency('libudev', version: '>= 175')
dbus_dep = dependency('dbus-1', version: '>= 1.1')
libndp_dep = dependency('libndp')

jansson_dep = dependency('jansson', version: '>= 2.5', required: false)
config_h.set10('WITH_JANSSON', jansson_dep.found())

if jansson_dep.found()
  jansson_libdir = jansson_dep.get_pkgconfig_variable('libdir')
  res = run_command(find_program('eu-readelf', 'readelf'), '-d', join_paths(jansson_libdir, 'libjansson.so'))
  jansson_soname = ''
  foreach line: res.stdout().split('\n')
    if line.strip().contains('SONAME')
       jansson_soname = line.split('[')[1].split(']')[0]
    endif
  endforeach
  assert(jansson_soname != '', 'Unable to determine Jansson SONAME')
  config_h.set_quoted('JANSSON_SONAME', jansson_soname)
endif

libsystemd_dep = dependency('libsystemd', version: '>= 209', required: false)
libsystemd_login_dep = dependency('libsystemd-login', version: '>= 183', required: false)

config_h.set10('HAVE_LIBSYSTEMD', libsystemd_dep.found())

systemd_dep = dependency('systemd', required: false)
have_systemd_200 = systemd_dep.found() and systemd_dep.version().version_compare('>= 200')

gio_unix_dep = dependency('gio-unix-2.0', version: '>= 2.40')

glib_dep = declare_dependency(
  dependencies: [
    gio_unix_dep,
    dependency('gmodule-2.0'),
  ],
  compile_args: [
    '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_40',
    '-DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_40',
  ]
)

if run_command('test', '-e', '/etc/sysconfig/network-scripts').returncode() == 0
  distro = 'redhat'
elif run_command('test', '-e', '/etc/SuSE-release').returncode() == 0
  distro = 'suse'
elif run_command('test', '-e', '/etc/debian_version').returncode() == 0
  distro = 'debian'
elif run_command('test', '-e', '/etc/gentoo-release').returncode() == 0
  distro = 'gentoo'
else
  distro = 'unknown'
endif

enable_ifcfg_rh = get_option('ifcfg_rh') or (distro == 'redhat')
enable_ifupdown = get_option('ifupdown') or (distro == 'debian')

config_plugins_default = get_option('config_plugins_default')
if config_plugins_default == ''
  config_plugins = []

  if enable_ifcfg_rh
    config_plugins += ['ifcfg-rh']
  endif

  if enable_ifupdown
    config_plugins += ['ifupdown']
  endif

  config_plugins_default = ','.join(config_plugins)
endif
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_PLUGINS', config_plugins_default)

config_h.set_quoted('NM_DIST_VERSION', dist_version)

enable_wifi = get_option('wifi')

enable_iwd = get_option('iwd')
if enable_iwd
  assert(enable_wifi, 'Enabling iwd support requires Wi-Fi support as well')
endif
config_h.set10('WITH_IWD', enable_iwd)

enable_wext = get_option('wext')
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

udev_dir = get_option('udev_dir')
install_udev_dir = (udev_dir != 'no')

if install_udev_dir and udev_dir == ''
  udev_dir = dependency('udev').get_pkgconfig_variable('udevdir')
endif

systemd_system_unit_dir = get_option('systemdsystemunitdir')
install_systemd_unit_dir = (systemd_system_unit_dir != 'no')

if install_systemd_unit_dir and systemd_system_unit_dir == ''
  assert(systemd_dep.found(), 'systemd required but not found, please provide a valid systemd user unit dir or disable it')
  systemd_system_unit_dir = systemd_dep.get_pkgconfig_variable('systemdsystemunitdir')
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
  elif session_tracking_consolekit
    suspend_resume = 'consolekit'
  else
    suspend_resume = 'upower'
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
elif suspend_resume == 'upower'
  config_h.set('SUSPEND_RESUME_UPOWER', true)
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

# eBPF support
ebpf_opt = get_option('ebpf')
# 'auto' means 'false', because there are still issues.
if ebpf_opt != 'true'
  enable_ebpf = false
else
  enable_ebpf = true
  if not cc.has_header('linux/bpf.h')
    assert(ebpf_opt != 'true', 'eBPF requires kernel support')
    enable_ebpf = false
  endif
endif

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

enable_json_validation = get_option('json_validation')
if enable_json_validation
  assert(jansson_dep.found(), 'jansson is needed for team configuration validation. Use -Djson_validation=false to disable it')
endif
config_h.set10('WITH_JSON_VALIDATION', enable_json_validation)

# polkit
enable_polkit = get_option('polkit')
if enable_polkit
  # FIXME: policydir should be relative to `datadir`, not `prefix`. Fixed in https://gitlab.freedesktop.org/polkit/polkit/merge_requests/2
  polkit_dir = dependency('polkit-gobject-1').get_pkgconfig_variable('policydir', define_variable: ['prefix', nm_prefix])
endif

config_default_main_auth_polkit = enable_polkit.to_string()
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT', config_default_main_auth_polkit)

enable_modify_system = get_option('modify_system')

enable_polkit_agent = get_option('polkit_agent')
if enable_polkit_agent
  polkit_agent_dep = dependency('polkit-agent-1', version: '>= 0.97')
endif
config_h.set10('WITH_POLKIT_AGENT', enable_polkit_agent)

crypto_gnutls_dep = dependency('gnutls', version: '>= 2.12', required: false)
crypto_nss_dep = dependency('nss', required: false)

crypto = get_option('crypto')
if crypto == 'nss'
  assert(crypto_nss_dep.found(), 'Requires gnutls crypto support')
elif crypto == 'gnutls'
  assert(crypto_gnutls_dep.found(), 'Requires gnutls crypto support')
else
  error('bug')
endif

dbus_conf_dir = get_option('dbus_conf_dir')
if dbus_conf_dir == ''
  assert(dbus_dep.found(), 'D-Bus required but not found, please provide a valid system bus config dir')
  dbus_conf_dir = join_paths(dbus_dep.get_pkgconfig_variable('sysconfdir'), 'dbus-1', 'system.d')
endif

dbus_ifaces_dir = dbus_dep.get_pkgconfig_variable('interfaces_dir',  define_variable: ['datadir', nm_datadir])
dbus_sys_dir = dbus_dep.get_pkgconfig_variable('system_bus_services_dir', define_variable: ['datadir', nm_datadir])

# pppd
enable_ppp = get_option('ppp')
if enable_ppp
  assert(cc.has_header('pppd/pppd.h'), 'couldn\'t find pppd.h. pppd development headers are required')

  pppd_path = get_option('pppd')
  if pppd_path == ''
    pppd = find_program('pppd', '/sbin/pppd', '/usr/sbin/pppd', required: false)
    assert(pppd.found(), 'pppd required but not found, please provide a valid pppd path or use -Dppp=false to disable it')
    pppd_path = pppd.path()
  endif

  config_h.set_quoted('PPPD_PATH', pppd_path)

  pppd_plugin_dir = get_option('pppd_plugin_dir')
  if pppd_plugin_dir == ''
    pppd_plugin_dir = join_paths(nm_libdir, 'pppd', '2.4.5')
  endif
endif
config_h.set10('WITH_PPP', enable_ppp)

# ModemManager1 with libmm-glib
enable_modem_manager = get_option('modem_manager')
if enable_modem_manager
  mm_glib_dep = dependency('mm-glib', version: '>= 0.7.991')
endif

# Bluez5 DUN support
enable_bluez5_dun = get_option('bluez5_dun')
if enable_bluez5_dun
  bluez5_dep = dependency('bluez', version: '>= 5', required: false)
  assert(bluez5_dep.found(), 'Bluez 5.x development headers are required')
endif
config_h.set10('WITH_BLUEZ5_DUN', enable_bluez5_dun)

# OFONO
enable_ofono = get_option('ofono')
config_h.set10('WITH_OFONO', enable_ofono)

# DHCP client support
config_dhcp_default = get_option('config_dhcp_default')
config_h.set_quoted('NM_CONFIG_DEFAULT_MAIN_DHCP', config_dhcp_default)
dhcp_summary = ''
foreach client : [ 'dhclient', 'dhcpcd', 'dhcpcanon' ]
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
        client_path = client_prog.path()
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
  endif
  dhcp_summary += '\n'
endforeach

# Open vSwitch integration
enable_ovs = get_option('ovs')
if enable_ovs
  assert(jansson_dep.found(), 'jansson is needed for Open vSwitch integration. Use -Dovs=false to disable it')
endif

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
                          '/usr/local/sbin' + prog_name,
                          required : false)
      if prog.found()
        prog_path = prog.path()
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
dnssec_ts_paths = ['/usr/local/libexec',
                   '/usr/local/lib',
                   '/usr/local/lib/dnssec-trigger',
                   '/usr/libexec',
                   '/usr/lib',
                   '/usr/lib/dnssec-trigger']

# 0: cmdline option, 1: paths, 2: fallback
progs = [['iptables',       default_paths,   '/sbin/iptables'],
         ['dnsmasq',        default_paths,   ''],
         ['dnssec_trigger', dnssec_ts_paths, join_paths(nm_libexecdir, 'dnssec-trigger-script') ],
        ]

foreach prog : progs
  path = get_option(prog[0])
  if path == ''
    search_paths = [ prog[0] ]
    foreach path : prog[1]
      search_paths += (path + '/' + prog[0])
    endforeach
    exe = find_program(search_paths, required : false)
    path = exe.found() ? exe.path() : prog[2]
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

enable_concheck = get_option('concheck')
if enable_concheck
  libcurl_dep = dependency('libcurl', version: '>= 7.24.0', required: false)
  assert(libcurl_dep.found(), 'concheck requires libcurl library. Use -Dconcheck=false to disable it')
endif
config_h.set10('WITH_CONCHECK', enable_concheck)

enable_nmcli = get_option('nmcli')
if enable_nmcli
  # FIXME: check for readline
  # AX_LIB_READLINE
  readline_dep = declare_dependency(link_args: '-lreadline')
  '''
  foreach readline_lib: ['-lreadline', '-ledit', '-leditline']
    if not is_variable('readline_dep')
      foreach termcap_lib: ['', '-lncurses', '-ltermcap', '-lcurses']
        test_dep = declare_dependency(link_args: ' '.join([readline_lib, termcap_lib]))
        if cc.has_function('readline', dependencies: test_dep) and cc.has_header('readline', dependencies: test_dep)
          readline_dep = test_dep
        endif
      endforeach
    endif
  endforeach
  '''
  assert(readline_dep.found(), 'readline library with terminfo support is required (one of readline, edit, or editline, AND one of ncurses, curses, or termcap)')
endif

enable_nmtui = get_option('nmtui')
if enable_nmtui
  newt_dep = dependency('libnewt', version: '>= 0.52.15', required: false)
  assert(newt_dep.found(), 'You must have libnewt installed to build nmtui. Use -Dnmtui=false to disable it')
endif

more_asserts = get_option('more_asserts')
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

generic_support_src = 'int main() { int a = 0; int b = _Generic (a, int: 4); return b + a; };'
config_h.set10('_NM_CC_SUPPORT_GENERIC', cc.compiles(generic_support_src))

auto_support_src = 'int main() { int a = 0; __auto_type b = a; return b + a; };'
config_h.set10('_NM_CC_SUPPORT_AUTO_TYPE', cc.compiles(auto_support_src))

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

# Tests, utilities and documentation
tests = get_option('tests')
enable_tests = (tests != 'no')
require_root_tests = (tests == 'root')
test_script = find_program(join_paths(meson.source_root(), 'tools', 'run-nm-test.sh'))

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
    valgrind_suppressions_path = join_paths(meson.source_root(), 'valgrind.suppressions')
  endif
endif

test_args = [
  '--called-from-make',
  meson.build_root(),
  '',
  enable_valgrind ? valgrind.path() : '',
  enable_valgrind ? valgrind_suppressions_path : '',
  '--launch-dbus=auto',
]

py3 = import('python3')
python = py3.find_python()

if python.found()
  config_h.set_quoted('TEST_NM_PYTHON', python.path())
endif

# check if we can build setting property documentation
'''
build_docs=no
if test -n "$INTROSPECTION_MAKEFILE"; then
  # If g-i is installed we know we have python, but we might not have pygobject
  if ! "$PYTHON" -c 'from gi.repository import GObject' >& /dev/null; then
    AC_MSG_ERROR(["--enable-introspection aims to build the settings documentation. This requires GObject introspection for python (pygobject)])
  fi

  AC_PATH_PROG(PERL, perl)
  if test -z "$PERL"; then
    AC_MSG_ERROR([--enable-introspection requires perl])
  fi
  AC_PATH_PROG(XSLTPROC, xsltproc)
  if test -z "$XSLTPROC"; then
    AC_MSG_ERROR([--enable-introspection requires xsltproc])
  fi

  have_introspection=yes
  if test "$enable_gtk_doc" = "yes"; then
    build_docs=yes
  fi
else
  if test "$enable_gtk_doc" = "yes"; then
    # large parts of the documentation require introspection/pygobject to extract
    # the documentation out of the source files. You cannot enable gtk-doc without alone.
    AC_MSG_ERROR(["--with-gtk-doc requires --enable-introspection"])
  fi
  have_introspection=no
fi
'''

gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

po_dir = join_paths(meson.source_root(), 'po')

intltool_merge = find_program('intltool-merge')
intltool_cache = join_paths(po_dir, '.intltool-merge-cache')
intltool_desktop_cmd = [intltool_merge, '-d', '-u', '-c', intltool_cache, po_dir, '@INPUT@', '@OUTPUT@']
intltool_xml_cmd = [intltool_merge, '-x', '-u', '-c', intltool_cache, po_dir, '@INPUT@', '@OUTPUT@']

perl = find_program('perl')
xsltproc = find_program('xsltproc')

check_exports = find_program(join_paths(meson.source_root(), 'tools', 'check-exports.sh'))

content_files = []

# FIXME: every plugin calls to this:
'''
set_sanitizer_env = \
        [ -n "$(SANITIZER_ENV)" ] && export $(SANITIZER_ENV) ; \
        if [ -n "$(1)" ] && echo $(CFLAGS) | grep -e -fsanitize=address ; then \
                export LD_PRELOAD="$${LD_PRELOAD}:$$(ldd $(1) | grep libasan\.so\.. -o | head -n 1)"; \
        fi

check_so_symbols = \
        $(call set_sanitizer_env,$(1)); \
        LD_BIND_NOW=1 LD_PRELOAD=$${LD_PRELOAD}:$(1) $(builddir)/src/NetworkManager --version >/dev/null
'''

top_inc = include_directories('.')

subdir('introspection')
subdir('shared')
subdir('libnm-core')
subdir('libnm')
subdir('src')
subdir('dispatcher')
subdir('clients')
subdir('data')
subdir('po')

if enable_vapi
  subdir('vapi')
endif

subdir('examples/C/glib')

enable_qt = get_option('qt')
if enable_qt
  add_languages('cpp')
  subdir('examples/C/qt')
endif

enable_docs = get_option('docs')

if enable_docs
  assert(enable_introspection, '-Ddocs=true requires -Dintrospection=true')
  assert(meson.version().version_compare('>= 0.46.0'), '-Ddocs requires meson >= 0.46')
  subdir('man')
  subdir('docs')
endif

config = 'config.h'

configure_file(
  input: config + '.meson',
  output: config,
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
config_extra_h.set_quoted('NM_BUILD_BUILDDIR', meson.build_root())
config_extra_h.set_quoted('NM_BUILD_SRCDIR',   meson.source_root())
if enable_ppp
    config_extra_h.set_quoted('PPPD_PLUGIN_DIR', pppd_plugin_dir)
endif
config_extra_h.set_quoted('PREFIX',            nm_prefix)
config_extra_h.set_quoted('RUNSTATEDIR',       nm_runstatedir)
config_extra_h.set_quoted('SYSCONFDIR',        nm_sysconfdir)

configure_file(
  input: 'config-extra.h.meson',
  output: 'config-extra.h',
  configuration: config_extra_h,
)

meson.add_install_script(
  join_paths('tools', 'meson-post-install.sh'),
  nm_datadir,
  nm_bindir,
  nm_pkgconfdir,
  nm_pkglibdir,
  nm_pkgstatedir,
  enable_docs ? 'install_docs' : '',
  nm_mandir,
)

output = '\nSystem paths:\n'
output += '  prefix: ' + nm_prefix + '\n'
output += '  exec_prefix: ' + nm_prefix + '\n'
output += '  systemdunitdir: ' + systemd_system_unit_dir + '\n'
output += '  nmbinary: ' + nm_pkgsbindir + '\n'
output += '  nmconfdir: ' + nm_pkgconfdir + '\n'
output += '  nmlibdir: ' + nm_pkglibdir + '\n'
output += '  nmdatadir: ' + nm_pkgdatadir + '\n'
output += '  nmstatedir: ' + nm_pkgstatedir + '\n'
output += '  nmrundir: ' + nm_pkgrundir + '\n'
output += '  nmvpndir: ' + nm_vpndir + '\n'
output += '  nmplugindir: ' + nm_plugindir + '\n'
output += '\nPlatform:\n'
output += '  session tracking: ' + ','.join(session_trackers) + '\n'
output += '  suspend/resume: ' + suspend_resume + '\n'
output += '  policykit: ' + enable_polkit.to_string()
if enable_polkit
  modify = (enable_modify_system ? 'permissive' : 'restrictive')
  output += ' (' + modify + ' modify.system) (default: main.auth-polkit=true)'
endif
output += '\n'
output += '  polkit agent: ' + enable_polkit_agent.to_string() + '\n'
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
output += '  modemmanager-1: ' + enable_modem_manager.to_string() + '\n'
output += '  ofono: ' + enable_ofono.to_string() + '\n'
output += '  concheck: ' + enable_concheck.to_string() + '\n'
output += '  libteamdctl: ' + enable_teamdctl.to_string() + '\n'
output += '  ovs: ' + enable_ovs.to_string() + '\n'
output += '  nmcli: ' + enable_nmcli.to_string() + '\n'
output += '  nmtui: ' + enable_nmtui.to_string() + '\n'
output += '\nConfiguration_plugins (main.plugins=' + config_plugins_default + ')\n'
output += '  ifcfg-rh: ' + enable_ifcfg_rh.to_string() + '\n'
output += '  ifupdown: ' + enable_ifupdown.to_string() + '\n'
output += '\nHandlers for /etc/resolv.conf:\n' + resolv_conf_summary
output += '\n'
output += '  config-dns-rc-manager-default: ' + config_dns_rc_manager_default + '\n'
output += '\nDHCP clients (default ' + config_dhcp_default + '):\n' + dhcp_summary
output += '\n'
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
output += '  LTO: ' + enable_lto.to_string() + '\n'
output += '  Linker garbage collection: ' + enable_ld_gc.to_string() + '\n'
output += '  JSON validation for libnm: ' + enable_json_validation.to_string() + '\n'
output += '  crypto: ' + crypto + ' (have-gnutls: ' + crypto_gnutls_dep.found().to_string() + ', have-nss: ' + crypto_nss_dep.found().to_string() + ')\n'
output += '  sanitizers: ' + get_option('b_sanitize') + '\n'
output += '  Mozilla Public Suffix List: ' + enable_libpsl.to_string() + '\n'
output += '  vapi: ' + enable_vapi.to_string() + '\n'
output += '  ebpf: ' + enable_ebpf.to_string() + '\n'
message(output)
