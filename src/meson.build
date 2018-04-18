#
# target: libnacd.so
# We build both, a static and a shared library. We want our tests to get access
# to internals, so we link them statically.
#

libnacd_private = static_library('nacd-private',
                                 ['n-acd.c'],
                                 c_args: [
                                        '-fvisibility=hidden',
                                        '-fno-common'
                                 ],
                                 dependencies: [
                                        dep_clist,
                                        dep_csiphash,
                                 ],
                                 pic: true)
install_headers('n-acd.h')
libnacd_symfile = join_paths(meson.current_source_dir(), 'libnacd.sym')
libnacd_shared = shared_library('nacd',
                                dependencies: dep_csiphash,
                                objects: libnacd_private.extract_all_objects(),
                                install: true,
                                soversion: 0,
                                link_depends: libnacd_symfile,
                                link_args: [
                                        '-Wl,--no-undefined',
                                        '-Wl,--version-script=@0@'.format(libnacd_symfile)
                                ])
mod_pkgconfig.generate(libraries: libnacd_shared,
                       version: meson.project_version(),
                       name: 'libnacd',
                       filebase: 'libnacd',
                       description: 'IPv4 Address Conflict Detection')

#
# target: test-api
# The test-api program explicitly links against the shared library, since it
# tests for symbol visibility.
#

test_api = executable('test-api',
                      ['test-api.c'],
                      link_with: libnacd_shared)
test('API Symbol Visibility', test_api)

#
# target: test-*
# All other tests are listed here. They link against the static library, so
# they can access internals for verification.
#

test_basic = executable('test-basic',
                        ['test-basic.c'],
                        link_with: libnacd_private)
test('Basic API Behavior', test_basic)

test_loopback = executable('test-loopback',
                           ['test-loopback.c'],
                           link_with: libnacd_private)
test('Echo Suppression via Loopback', test_loopback)

test_twice = executable('test-twice',
                        ['test-twice.c'],
                        link_with: libnacd_private)
test('Two ACD in Parallel', test_twice)

test_unplug = executable('test-unplug',
                         ['test-unplug.c'],
                         link_with: libnacd_private)
test('Async Interface Hotplug', test_unplug)

test_unused = executable('test-unsed',
                         ['test-unused.c'],
                         link_with: libnacd_private)
test('Unconflicted ACD', test_unused)
