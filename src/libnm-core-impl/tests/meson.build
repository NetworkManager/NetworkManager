# SPDX-License-Identifier: LGPL-2.1-or-later

enum_sources = gnome.mkenums_simple(
  'nm-core-tests-enum-types',
  sources: 'test-general-enums.h',
  identifier_prefix: nm_id_prefix,
  body_prefix: '#include "libnm-core-impl/nm-default-libnm-core.h"',
)

test_units = [
  'test-compare',
  'test-crypto',
  'test-general',
  'test-keyfile',
  'test-secrets',
  'test-setting',
  'test-settings-defaults',
]

foreach test_unit: test_units
  exe = executable(
    'libnm-core-' + test_unit,
    [test_unit + '.c'] + enum_sources,
    include_directories: [
      libnm_core_impl_inc,
    ],
    dependencies: [
      libnm_core_public_dep,
    ],
    link_with: [
      libnm_core_aux_intern,
      libnm_core_impl,
      libnm_crypto,
      libnm_base,
      libnm_systemd_shared,
      libnm_log_null,
      libnm_glib_aux,
      libnm_std_aux,
      libc_siphash,
    ],
  )

  test(
    'src/libnm-core-impl/tests/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endforeach
