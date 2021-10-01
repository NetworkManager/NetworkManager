#
# target: libcstdaux.so
# (No .so is built so far, since we are header-only. This might change in the
#  future, if we add more complex helpers.)
#

libcstdaux_dep = declare_dependency(
        include_directories: include_directories('.'),
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('c-stdaux.h')

        mod_pkgconfig.generate(
                version: meson.project_version(),
                name: 'libcstdaux',
                filebase: 'libcstdaux',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], dependencies: libcstdaux_dep)
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libcstdaux_dep)
test('Basic API Behavior', test_basic)
