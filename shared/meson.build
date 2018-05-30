shared_inc = include_directories('.')

shared_c_siphash = static_library(
    'c-siphash',
    sources: 'c-siphash/src/c-siphash.c',
)

shared_c_siphash_dep = declare_dependency(
    include_directories: shared_inc,
    link_with: shared_c_siphash,
)

shared_n_acd = static_library(
    'n-acd',
    sources: 'n-acd/src/n-acd.c',
    include_directories: [
        include_directories('c-siphash/src'),
        include_directories('c-list/src'),
    ],
    dependencies: shared_c_siphash_dep,
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

shared_nm_utils_nm_meta_setting_c = files('nm-meta-setting.c')

shared_nm_test_utils_impl_c = files('nm-test-utils-impl.c')

shared_nm_utils_nm_vpn_plugin_utils_c = files('nm-utils/nm-vpn-plugin-utils.c')

shared_files_libnm_core = files('''
    c-siphash/src/c-siphash.c
    nm-utils/c-list-util.c
    nm-utils/nm-dedup-multi.c
    nm-utils/nm-enum-utils.c
    nm-utils/nm-hash-utils.c
    nm-utils/nm-random-utils.c
    nm-utils/nm-shared-utils.c
    nm-utils/nm-udev-utils.c
'''.split())

shared_files_clients_common = files('''
    c-siphash/src/c-siphash.c
    nm-utils/nm-enum-utils.c
    nm-utils/nm-hash-utils.c
    nm-utils/nm-random-utils.c
    nm-utils/nm-shared-utils.c
'''.split())

shared_files_libnm_util = files('''
    nm-utils/nm-shared-utils.c
'''.split())

shared_files_libnm_glib = files('''
    nm-utils/nm-udev-utils.c
'''.split())

shared_dep = declare_dependency(
    include_directories: [
        top_inc,
        shared_inc,
    ],
    dependencies: glib_dep,
)
