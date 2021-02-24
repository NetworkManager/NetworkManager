#
# target: libndhcp4.so
#

libndhcp4_symfile = join_paths(meson.current_source_dir(), 'libndhcp4.sym')

libndhcp4_deps = [
        dep_clist,
        dep_csiphash,
        dep_cstdaux,
]

libndhcp4_private = static_library(
        'ndhcp4-private',
        [
                'n-dhcp4-c-connection.c',
                'n-dhcp4-c-lease.c',
                'n-dhcp4-c-probe.c',
                'n-dhcp4-client.c',
                'n-dhcp4-incoming.c',
                'n-dhcp4-outgoing.c',
                'n-dhcp4-s-connection.c',
                'n-dhcp4-s-lease.c',
                'n-dhcp4-server.c',
                'n-dhcp4-socket.c',
                'util/link.c',
                'util/netns.c',
                'util/packet.c',
                'util/socket.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common'
        ],
        dependencies: libndhcp4_deps,
        pic: true,
)

libndhcp4_shared = shared_library(
        'ndhcp4',
        objects: libndhcp4_private.extract_all_objects(),
        dependencies: libndhcp4_deps,
        install: not meson.is_subproject(),
        soversion: 0,
        link_depends: libndhcp4_symfile,
        link_args: [
                '-Wl,--no-undefined',
                '-Wl,--version-script=@0@'.format(libndhcp4_symfile)
        ],
)

libndhcp4_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libndhcp4_private,
        dependencies: libndhcp4_deps,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('n-dhcp4.h')

        mod_pkgconfig.generate(
                libraries: libndhcp4_shared,
                version: meson.project_version(),
                name: 'libndhcp4',
                filebase: 'libndhcp4',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libndhcp4_shared)
test('API Symbol Visibility', test_api)

test_connection = executable('test-connection', ['test-connection.c'], dependencies: libndhcp4_dep)
test('Connection Handling', test_connection)

test_message = executable('test-message', ['test-message.c'], dependencies: libndhcp4_dep)
test('Message Handling', test_message)

test_run_client = executable('test-run-client', ['test-run-client.c'], dependencies: libndhcp4_dep)
test('Client Runner', test_run_client, args: ['--test'])

test_socket = executable('test-socket', ['test-socket.c'], dependencies: libndhcp4_dep)
test('Socket Handling', test_socket)

test_util_packet = executable('test-util-packet', ['util/test-packet.c'], dependencies: libndhcp4_dep)
test('Packet Utility Library', test_util_packet)
