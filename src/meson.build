#
# target: libcstdaux.so
# (No .so is built so far, since we are header-only. This might change in the
#  future, if we add more complex helpers.)
#

libcstdaux_vars = {
        'cflags': ' '.join(cflags),
        'version-scripts': use_version_scripts,
}

libcstdaux_dep = declare_dependency(
        include_directories: include_directories('.'),
        variables: libcstdaux_vars,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers(
                'c-stdaux.h',
                'c-stdaux-generic.h',
                'c-stdaux-gnuc.h',
                'c-stdaux-unix.h',
        )

        mod_pkgconfig.generate(
                description: project_description,
                filebase: 'libcstdaux-'+major,
                name: 'libcstdaux',
                unescaped_variables: libcstdaux_vars,
                version: meson.project_version(),
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], dependencies: libcstdaux_dep)
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libcstdaux_dep)
test('Basic API Behavior', test_basic)
