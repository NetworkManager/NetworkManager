#
# target: libcsiphash.so
#

libcsiphash_symfile = join_paths(meson.current_source_dir(), 'libcsiphash.sym')

libcsiphash_deps = [
        dep_cstdaux,
]

libcsiphash_private = static_library(
        'csiphash-private',
        [
                'c-siphash.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: libcsiphash_deps,
        pic: true,
)

libcsiphash_shared = shared_library(
        'csiphash',
        objects: libcsiphash_private.extract_all_objects(),
        dependencies: libcsiphash_deps,
        install: not meson.is_subproject(),
        soversion: 0,
        link_depends: libcsiphash_symfile,
        link_args: [
                '-Wl,--no-undefined',
                '-Wl,--version-script=@0@'.format(libcsiphash_symfile),
        ],
)

libcsiphash_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libcsiphash_private,
        dependencies: libcsiphash_deps,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('c-siphash.h')

        mod_pkgconfig.generate(
                libraries: libcsiphash_shared,
                version: meson.project_version(),
                name: 'libcsiphash',
                filebase: 'libcsiphash',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libcsiphash_shared)
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libcsiphash_dep)
test('Basic API Behavior', test_basic)
