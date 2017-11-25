shared_inc = include_directories(
  '.',
  'nm-utils'
)

version_conf = configuration_data()
version_conf.set('NM_MAJOR_VERSION', nm_major_version)
version_conf.set('NM_MINOR_VERSION', nm_minor_version)
version_conf.set('NM_MICRO_VERSION', nm_micro_version)

version = 'nm-version-macros.h'

version_header = configure_file(
  input: version + '.in',
  output: version,
  configuration: version_conf
)

shared_meta_setting = files('nm-meta-setting.c')

shared_test_utils = files('nm-test-utils-impl.c')

shared_siphash = files('nm-utils/siphash24.c')

shared_udev_utils = files('nm-utils/nm-udev-utils.c')

shared_utils = files(
  'nm-utils/nm-enum-utils.c',
  'nm-utils/nm-hash-utils.c',
  'nm-utils/nm-random-utils.c',
  'nm-utils/nm-shared-utils.c'
)

shared_vpn_plugin_utils = files('nm-utils/nm-vpn-plugin-utils.c')

shared_sources = shared_utils + shared_meta_setting + shared_udev_utils + files(
  'nm-utils/c-list-util.c',
  'nm-utils/nm-dedup-multi.c'
)
