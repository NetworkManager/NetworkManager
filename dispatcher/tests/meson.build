test_unit = 'test-dispatcher-envp'

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc,
  dispatcher_inc
]

cflags = '-DSRCDIR="@0@"'.format(meson.current_source_dir())

exe = executable(
  test_unit,
  [test_unit + '.c', libnm_core_enums_h],
  include_directories: incs,
  dependencies: glib_dep,
  c_args: cflags,
  link_with: libnm_dispatcher_core
)

test(test_unit, exe)
