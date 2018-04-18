project('n-acd',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'buildtype=release',
                'c_std=c11',
        ])

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

sub_clist = subproject('c-list')
sub_csiphash = subproject('c-siphash')

dep_clist = sub_clist.get_variable('libclist_dep')
dep_csiphash = sub_csiphash.get_variable('libcsiphash_dep')

subdir('src')
