# SPDX-License-Identifier: LGPL-2.1-or-later

src_inc = include_directories('.')

###############################################################################

libc_siphash = static_library(
  'c-siphash',
  sources: 'c-siphash/src/c-siphash.c',
  include_directories: include_directories('c-stdaux/src'),
  c_args: '-std=c11',
)

libc_rbtree = static_library(
  'c-rbtree',
  sources: 'c-rbtree/src/c-rbtree.c',
  include_directories: include_directories('c-stdaux/src'),
  c_args: '-std=c11',
)

libn_acd = static_library(
  'n-acd',
  sources: files(
    'n-acd/src/n-acd.c',
    'n-acd/src/n-acd-probe.c',
    'n-acd/src/util/timer.c',
    enable_ebpf ? 'n-acd/src/n-acd-bpf.c' : 'n-acd/src/n-acd-bpf-fallback.c',
  ),
  include_directories: include_directories(
    'c-list/src',
    'c-rbtree/src',
    'c-siphash/src',
    'c-stdaux/src',
  ),
  c_args: [
    '-std=c11',
    '-D_GNU_SOURCE',
    '-DSO_ATTACH_BPF=50',
    '-Wno-pointer-arith',
    '-Wno-vla',
  ],
)

libn_dhcp4 = static_library(
  'n-dhcp4',
  sources: files(
    'n-dhcp4/src/n-dhcp4-c-connection.c',
    'n-dhcp4/src/n-dhcp4-c-lease.c',
    'n-dhcp4/src/n-dhcp4-client.c',
    'n-dhcp4/src/n-dhcp4-c-probe.c',
    'n-dhcp4/src/n-dhcp4-incoming.c',
    'n-dhcp4/src/n-dhcp4-outgoing.c',
    'n-dhcp4/src/n-dhcp4-socket.c',
    'n-dhcp4/src/util/packet.c',
    'n-dhcp4/src/util/socket.c',
  ),
  include_directories: include_directories(
    'c-list/src',
    'c-siphash/src',
    'c-stdaux/src',
  ),
  c_args: [
    '-std=c11',
    '-D_GNU_SOURCE',
    '-Wno-declaration-after-statement',
    '-Wno-pointer-arith',
  ],
)

###############################################################################

subdir('libnm-std-aux')
subdir('libnm-glib-aux')
subdir('libnm-log-null')
subdir('libnm-log-core')
subdir('libnm-systemd-shared')
subdir('libnm-systemd-core')
subdir('libnm-udev-aux')
subdir('libnm-base')
subdir('libnm-platform')
subdir('libnm-core-public')
subdir('libnm-core-intern')
subdir('libnm-core-aux-intern')
subdir('libnm-core-impl')
subdir('libnm-core-aux-extern')
subdir('libnm-client-public')
subdir('libnm-client-impl')
subdir('libnm-client-aux-extern')
subdir('libnmc-base')
subdir('libnmc-setting')
if enable_nmtui
  subdir('libnmt-newt')
endif
subdir('nmcli')
subdir('nm-dispatcher')
subdir('nm-daemon-helper')
subdir('nm-online')
if enable_nmtui
  subdir('nmtui')
endif
subdir('nm-initrd-generator')
if enable_nm_cloud_setup
  subdir('nm-cloud-setup')
endif
subdir('core')
subdir('contrib')

if enable_tests
  subdir('libnm-client-test')
  subdir('libnm-glib-aux/tests')
  subdir('libnm-platform/tests')
  subdir('libnm-core-impl/tests')
  subdir('libnm-client-impl/tests')
  subdir('libnm-client-aux-extern/tests')
  subdir('libnmc-setting/tests')
  subdir('nm-dispatcher/tests')
  subdir('nm-initrd-generator/tests')
  if enable_nm_cloud_setup
    subdir('nm-cloud-setup/tests')
  endif
  subdir('tests/client')
  subdir('contrib/tests')
endif
