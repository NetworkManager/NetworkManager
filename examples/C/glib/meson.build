# SPDX-License-Identifier: LGPL-2.1+

examples = [
  ['add-connection-gdbus', [libnm_enum_sources[1]], [uuid_dep]],
  ['add-connection-libnm', [], [libnm_dep]],
  ['get-active-connections-gdbus', [libnm_enum_sources[1]], []],
  ['get-ap-info-libnm', [], [libnm_dep]],
  ['list-connections-gdbus', [], []],
  ['list-connections-libnm', [], [libnm_dep]],
  ['monitor-nm-running-gdbus', [], []],
  ['monitor-nm-state-gdbus', [], []],
]

foreach example: examples
  executable(
    example[0],
    [example[0] + '.c'] + example[1],
    dependencies: [libnm_nm_default_dep] + example[2],
  )
endforeach
