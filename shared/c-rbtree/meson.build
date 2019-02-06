project(
        'c-rbtree',
        'c',
        version: '3',
        license: 'Apache',
        default_options: [
                'c_std=c11'
        ],
)
project_description = 'Intrusive Red-Black Tree Collection'

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

subdir('src')
