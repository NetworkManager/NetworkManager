#
# target: libcsiphash.so
#

libcsiphash_deffile = join_paths(meson.current_source_dir(), 'libcsiphash.def')
libcsiphash_symfile = join_paths(meson.current_source_dir(), 'libcsiphash.sym')

libcsiphash_deps = [
        dep_cstdaux,
]

libcsiphash_both = both_libraries(
        'csiphash-'+major,
        [
                'c-siphash.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: libcsiphash_deps,
        install: not meson.is_subproject(),
        link_args: dep_cstdaux.get_variable('version-scripts') == 'yes' ? [
                '-Wl,--version-script=@0@'.format(libcsiphash_symfile),
        ] : [],
        link_depends: libcsiphash_symfile,
        vs_module_defs: libcsiphash_deffile,
        soversion: 0,
)

libcsiphash_dep = declare_dependency(
        dependencies: libcsiphash_deps,
        include_directories: include_directories('.'),
        link_with: libcsiphash_both.get_static_lib(),
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('c-siphash.h')

        mod_pkgconfig.generate(
                description: project_description,
                filebase: 'libcsiphash-'+major,
                libraries: libcsiphash_both.get_shared_lib(),
                name: 'libcsiphash',
                version: meson.project_version(),
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libcsiphash_both.get_shared_lib())
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libcsiphash_dep)
test('Basic API Behavior', test_basic)
