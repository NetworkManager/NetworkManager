# SPDX-License-Identifier: LGPL-2.1-or-later

test(
  'check-local-tests-client',
  find_program(join_paths(source_root, 'src/tests/client/test-client.sh')),
  args: [
    build_root,
    source_root,
    python.path(),
  ],
  timeout: 120,
)
