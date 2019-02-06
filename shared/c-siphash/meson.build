project(
        'c-siphash',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'c_std=c11'
        ],
)
project_description = 'Streaming-capable SipHash Implementation'

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

subdir('src')
