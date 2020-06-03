project(
        'c-stdaux',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'c_std=c11'
        ],
)
project_description = 'Auxiliary macros and functions for the C standard library'

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

subdir('src')
