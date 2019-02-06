#
# target: libnacd.so
#

libnacd_symfile = join_paths(meson.current_source_dir(), 'libnacd.sym')

libnacd_deps = [
        dep_clist,
        dep_crbtree,
        dep_csiphash,
]

libnacd_sources = [
        'n-acd.c',
        'n-acd-probe.c',
        'util/timer.c',
]

if use_ebpf
        libnacd_sources += [
                'n-acd-bpf.c',
        ]
else
        libnacd_sources += [
                'n-acd-bpf-fallback.c',
        ]
endif

libnacd_private = static_library(
        'nacd-private',
        libnacd_sources,
        c_args: [
                '-fvisibility=hidden',
                '-fno-common'
        ],
        dependencies: libnacd_deps,
        pic: true,
)

libnacd_shared = shared_library(
        'nacd',
        objects: libnacd_private.extract_all_objects(),
        dependencies: libnacd_deps,
        install: not meson.is_subproject(),
        soversion: 0,
        link_depends: libnacd_symfile,
        link_args: [
                '-Wl,--no-undefined',
                '-Wl,--version-script=@0@'.format(libnacd_symfile)
        ],
)

libnacd_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libnacd_private,
        dependencies: libnacd_deps,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('n-acd.h')

        mod_pkgconfig.generate(
                libraries: libnacd_shared,
                version: meson.project_version(),
                name: 'libnacd',
                filebase: 'libnacd',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libnacd_shared)
test('API Symbol Visibility', test_api)

if use_ebpf
        test_bpf = executable('test-bpf', ['test-bpf.c'], dependencies: libnacd_dep)
        test('eBPF socket filtering', test_bpf)
endif

test_loopback = executable('test-loopback', ['test-loopback.c'], dependencies: libnacd_dep)
test('Echo Suppression via Loopback', test_loopback)

test_timer = executable('test-timer', ['util/test-timer.c'], dependencies: libnacd_dep)
test('Timer helper', test_timer)

#test_unplug = executable('test-unplug', ['test-unplug.c'], dependencies: libnacd_dep)
#test('Async Interface Hotplug', test_unplug)

test_veth = executable('test-veth', ['test-veth.c'], dependencies: libnacd_dep)
test('Parallel ACD instances', test_veth)
