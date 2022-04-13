project(
        'c-stdaux',
        'c',
        default_options: [
                'c_std=c11'
        ],
        license: 'Apache',
        version: '1.0.0',
)
major = meson.project_version().split('.')[0]
project_description = 'Auxiliary macros and functions for the C standard library'

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

subdir('src')

meson.override_dependency('libcstdaux-'+major, libcstdaux_dep, static: true)
