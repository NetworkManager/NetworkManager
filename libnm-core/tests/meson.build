# SPDX-License-Identifier: LGPL-2.1-or-later

enum_sources = gnome.mkenums_simple(
  'nm-core-tests-enum-types',
  sources: 'test-general-enums.h',
  identifier_prefix: nm_id_prefix,
  body_prefix: '#include "libnm-core/nm-default-libnm-core.h"',
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
    dependencies: [
      libnm_core_dep,
      libnm_core_nm_default_dep,
      libnm_base_dep,
    ],
    c_args: [
      '-DG_LOG_DOMAIN="test"',
    ],
    link_with: libnm_systemd_logging_stub,
  )

  test(
    'libnm-core/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endforeach
