#
# target: libcrbtree.so
#

libcrbtree_symfile = join_paths(meson.current_source_dir(), 'libcrbtree.sym')

libcrbtree_private = static_library(
        'crbtree-private',
        [
                'c-rbtree.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        pic: true,
)

libcrbtree_shared = shared_library(
        'crbtree',
        objects: libcrbtree_private.extract_all_objects(),
        install: not meson.is_subproject(),
        soversion: 0,
        link_depends: libcrbtree_symfile,
        link_args: [
                '-Wl,--no-undefined',
                '-Wl,--version-script=@0@'.format(libcrbtree_symfile),
        ],
)

libcrbtree_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libcrbtree_private,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('c-rbtree.h')

        mod_pkgconfig.generate(
                libraries: libcrbtree_shared,
                version: meson.project_version(),
                name: 'libcrbtree',
                filebase: 'libcrbtree',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libcrbtree_shared)
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libcrbtree_dep)
test('Basic API Behavior', test_basic)

test_map = executable('test-map', ['test-map.c'], dependencies: libcrbtree_dep)
test('Generic Map', test_map)

test_misc = executable('test-misc', ['test-misc.c'], dependencies: libcrbtree_dep)
test('Miscellaneous', test_misc)

test_parallel = executable('test-parallel', ['test-parallel.c'], dependencies: libcrbtree_dep)
test('Lockless Parallel Readers', test_parallel)

test_posix = executable('test-posix', ['test-posix.c'], dependencies: libcrbtree_dep)
test('Posix tsearch(3p) Comparison', test_posix)
