shared_inc = include_directories('.')

shared_c_siphash = static_library(
    'c-siphash',
    sources: 'c-siphash/src/c-siphash.c',
)

shared_c_siphash_dep = declare_dependency(
    include_directories: shared_inc,
    link_with: shared_c_siphash,
)

shared_c_rbtree = static_library(
    'c-rbtree',
    c_args: '-std=c11',
    sources: files('c-rbtree/src/c-rbtree.c',
                   'c-rbtree/src/c-rbtree.h',
                   'c-rbtree/src/c-rbtree-private.h'),
)

shared_c_rbtree_dep = declare_dependency(
    include_directories: shared_inc,
    link_with: shared_c_rbtree,
)


if enable_ebpf
    shared_n_acd_bpf_files = files('n-acd/src/n-acd-bpf.c')
else
    shared_n_acd_bpf_files = files('n-acd/src/n-acd-bpf-fallback.c')
endif

shared_n_acd = static_library(
    'n-acd',
    sources: files('n-acd/src/n-acd.c',
                   'n-acd/src/n-acd.h',
                   'n-acd/src/n-acd-private.h',
                   'n-acd/src/n-acd-probe.c',
                   'n-acd/src/util/timer.c',
                   'n-acd/src/util/timer.h')
             + shared_n_acd_bpf_files,
    c_args: [
        '-D_GNU_SOURCE',
        '-DSO_ATTACH_BPF=50',
        '-std=c11',
        '-Wno-pointer-arith',
        '-Wno-vla',
    ],
    include_directories: [
        include_directories('c-siphash/src'),
        include_directories('c-list/src'),
        include_directories('c-rbtree/src'),
    ],
    dependencies: [
        shared_c_siphash_dep,
        shared_c_rbtree_dep,
    ],
)

shared_n_acd_dep = declare_dependency(
    include_directories: shared_inc,
    link_with: shared_n_acd,
)

version_conf = configuration_data()
version_conf.set('NM_MAJOR_VERSION', nm_major_version)
version_conf.set('NM_MINOR_VERSION', nm_minor_version)
version_conf.set('NM_MICRO_VERSION', nm_micro_version)

version_header = configure_file(
    input: 'nm-version-macros.h.in',
    output: 'nm-version-macros.h',
    configuration: version_conf,
)

shared_nm_ethtool_utils_c = files('nm-ethtool-utils.c')

shared_nm_meta_setting_c = files('nm-meta-setting.c')

shared_nm_test_utils_impl_c = files('nm-test-utils-impl.c')

shared_nm_utils_nm_vpn_plugin_utils_c = files('nm-utils/nm-vpn-plugin-utils.c')

###############################################################################

shared_nm_utils_c_args = [
    '-DG_LOG_DOMAIN="@0@"'.format(libnm_name),
    '-DNETWORKMANAGER_COMPILATION=(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_LIB)',
]

shared_nm_utils_base = static_library(
    'nm-utils-base',
    sources: files('nm-utils/c-list-util.c',
                   'nm-utils/nm-dedup-multi.c',
                   'nm-utils/nm-enum-utils.c',
                   'nm-utils/nm-errno.c',
                   'nm-utils/nm-hash-utils.c',
                   'nm-utils/nm-io-utils.c',
                   'nm-utils/nm-random-utils.c',
                   'nm-utils/nm-secret-utils.c',
                   'nm-utils/nm-shared-utils.c',
                   'nm-utils/nm-time-utils.c'),
    c_args: shared_nm_utils_c_args,
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: [
        glib_dep,
    ],
)

shared_nm_utils_base_dep = declare_dependency(
    link_with: shared_nm_utils_base,
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: glib_dep,
)

shared_nm_utils_udev = static_library(
    'nm-utils-udev',
    sources: files('nm-utils/nm-udev-utils.c'),
    c_args: shared_nm_utils_c_args,
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: [
        glib_dep,
        shared_nm_utils_base_dep,
        libudev_dep,
    ],
)

shared_nm_utils_udev_dep = declare_dependency(
    link_with: shared_nm_utils_udev,
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: [
        glib_dep,
        shared_nm_utils_base_dep,
        libudev_dep,
    ],
)

###############################################################################

test_shared_general = executable(
  'nm-utils/tests/test-shared-general',
  [ 'nm-utils/tests/test-shared-general.c', ],
  c_args: [
      '-DNETWORKMANAGER_COMPILATION_TEST',
      '-DNETWORKMANAGER_COMPILATION=(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)',
    ],
  dependencies: shared_nm_utils_base_dep,
  link_with: shared_c_siphash,
)
test(
  'shared/nm-utils/test-shared-general',
  test_script,
  args: test_args + [test_shared_general.full_path()]
)

###############################################################################

libnm_systemd_shared = static_library(
  'nm-systemd-shared',
  sources: files(
    'systemd/src/basic/alloc-util.c',
    'systemd/src/basic/escape.c',
    'systemd/src/basic/env-file.c',
    'systemd/src/basic/env-util.c',
    'systemd/src/basic/ether-addr-util.c',
    'systemd/src/basic/extract-word.c',
    'systemd/src/basic/fd-util.c',
    'systemd/src/basic/fileio.c',
    'systemd/src/basic/fs-util.c',
    'systemd/src/basic/hash-funcs.c',
    'systemd/src/basic/hashmap.c',
    'systemd/src/basic/hexdecoct.c',
    'systemd/src/basic/hostname-util.c',
    'systemd/src/basic/in-addr-util.c',
    'systemd/src/basic/io-util.c',
    'systemd/src/basic/mempool.c',
    'systemd/src/basic/parse-util.c',
    'systemd/src/basic/path-util.c',
    'systemd/src/basic/prioq.c',
    'systemd/src/basic/process-util.c',
    'systemd/src/basic/random-util.c',
    'systemd/src/basic/socket-util.c',
    'systemd/src/basic/stat-util.c',
    'systemd/src/basic/string-table.c',
    'systemd/src/basic/string-util.c',
    'systemd/src/basic/strv.c',
    'systemd/src/basic/time-util.c',
    'systemd/src/basic/tmpfile-util.c',
    'systemd/src/basic/utf8.c',
    'systemd/src/basic/util.c',
    'systemd/nm-sd-utils-shared.c',
  ),
  include_directories: include_directories(
    'systemd/sd-adapt-shared',
    'systemd/src/basic',
  ),
  dependencies: shared_nm_utils_base_dep,
  c_args: [
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD_SHARED',
    '-DG_LOG_DOMAIN="libnm"',
  ],
)

libnm_systemd_shared_dep = declare_dependency(
  include_directories: include_directories(
    'systemd/sd-adapt-shared',
    'systemd/src/basic',
  ),
  dependencies: [
    shared_nm_utils_base_dep,
  ],
  link_with: [
    libnm_systemd_shared,
  ],
)

libnm_systemd_logging_stub = static_library(
  'nm-systemd-logging-stub',
  sources: files(
    'systemd/nm-logging-stub.c',
  ),
  include_directories: include_directories(
    'systemd/sd-adapt-shared',
    'systemd/src/basic',
  ),
  dependencies: shared_nm_utils_base_dep,
  c_args: [
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD_SHARED',
    '-DG_LOG_DOMAIN="libnm"',
  ],
)

libnm_systemd_shared_no_logging_dep = declare_dependency(
  dependencies: [
    libnm_systemd_shared_dep,
  ],
  link_with: [
    libnm_systemd_logging_stub,
  ],
)
