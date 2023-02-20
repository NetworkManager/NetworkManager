# SPDX-License-Identifier: LGPL-2.1-or-later

examples = [
  'add-connection-wired',
  'list-connections',
  'change-ipv4-addresses',
]


foreach example: examples
  file = example + '.cpp'
  executable(example,
    file,
    include_directories: libnm_core_public_inc,
    dependencies: [
      qtdep,
    ],
  )
endforeach
