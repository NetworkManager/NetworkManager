# SPDX-License-Identifier: LGPL-2.1-or-later

subdir('libnm')
subdir('api')

test(
  'check-docs',
  find_program(join_paths(source_root, 'tools', 'check-docs.sh')),
  args: [source_root, build_root],
)
