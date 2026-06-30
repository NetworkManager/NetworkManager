project(
        'c-rbtree',
        'c',
        default_options: [
                'c_std=c11'
        ],
        license: 'Apache',
        meson_version: '>=0.60.0',
        version: '3.2.0',
)
major = meson.project_version().split('.')[0]
project_description = 'Intrusive Red-Black Tree Collection'

mod_pkgconfig = import('pkgconfig')
use_ptrace = get_option('ptrace')

dep_cstdaux = dependency('libcstdaux-1', version: '>=1.5.0')
add_project_arguments(dep_cstdaux.get_variable('cflags').split(' '), language: 'c')

subdir('src')

meson.override_dependency('libcrbtree-'+major, libcrbtree_dep, static: true)
