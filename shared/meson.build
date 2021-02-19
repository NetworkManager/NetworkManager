# SPDX-License-Identifier: LGPL-2.1-or-later

shared_inc = include_directories('.')

glib_nm_default_dep = declare_dependency(
  include_directories: [
    shared_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
  ],
)

nm_test_utils_impl_source = files('nm-test-utils-impl.c')

nm_vpn_plugin_utils_source = files('nm-utils/nm-vpn-plugin-utils.c')
