# SPDX-License-Identifier: LGPL-2.1-or-later

examples = [
  ['add-connection-gdbus',         [uuid_dep]],
  ['add-connection-libnm',         []],
  ['get-active-connections-gdbus', []],
  ['get-ap-info-libnm',            []],
  ['list-connections-gdbus',       []],
  ['list-connections-libnm',       []],
  ['monitor-nm-running-gdbus',     []],
  ['monitor-nm-state-gdbus',       []],
  ['vpn-import-libnm',              []],
]

foreach example: examples
  executable(
    example[0],
    [example[0] + '.c'],
    dependencies: [
      libnm_dep,
    ] + example[1],
  )
endforeach
