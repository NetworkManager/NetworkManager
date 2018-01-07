test_unit = 'test-dispatcher-envp'

incs = [
  dispatcher_inc,
  libnm_inc
]

cflags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
]

exe = executable(
  test_unit,
  test_unit + '.c',
  include_directories: incs,
  dependencies: nm_core_dep,
  c_args: cflags,
  link_with: libnm_dispatcher_core
)

test(test_unit, exe)
