#
# target: libcrbtree.so
#

libcrbtree_symfile = join_paths(meson.current_source_dir(), 'libcrbtree.sym')

libcrbtree_deps = [
        dep_cstdaux,
]

libcrbtree_both = both_libraries(
        'crbtree-'+major,
        [
                'c-rbtree.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: libcrbtree_deps,
        install: not meson.is_subproject(),
        link_args: dep_cstdaux.get_variable('version_scripts') == 'yes' ? [
                '-Wl,--version-script=@0@'.format(libcrbtree_symfile),
        ] : [],
        link_depends: libcrbtree_symfile,
        soversion: 0,
)

libcrbtree_dep = declare_dependency(
        dependencies: libcrbtree_deps,
        include_directories: include_directories('.'),
        link_with: libcrbtree_both.get_static_lib(),
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('c-rbtree.h')

        mod_pkgconfig.generate(
                description: project_description,
                filebase: 'libcrbtree-'+major,
                libraries: libcrbtree_both.get_shared_lib(),
                name: 'libcrbtree',
                version: meson.project_version(),
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libcrbtree_both.get_shared_lib())
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libcrbtree_dep)
test('Basic API Behavior', test_basic)

test_map = executable('test-map', ['test-map.c'], dependencies: libcrbtree_dep)
test('Generic Map', test_map)

test_misc = executable('test-misc', ['test-misc.c'], dependencies: libcrbtree_dep)
test('Miscellaneous', test_misc)

if use_ptrace
        test_parallel = executable('test-parallel', ['test-parallel.c'], dependencies: libcrbtree_dep)
        test('Lockless Parallel Readers', test_parallel)

        test_posix = executable('test-posix', ['test-posix.c'], dependencies: libcrbtree_dep)
        test('Posix tsearch(3p) Comparison', test_posix)
endif
