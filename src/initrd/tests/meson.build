test_units = [
  'test-ibft-reader',
  'test-cmdline-reader',
]

cflags = [
  '-DTEST_INITRD_DIR="@0@"'.format(meson.current_source_dir()),
]

foreach test_unit : test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_nm_dep,
    c_args: cflags,
    link_with: libnmi_core,
  )
  test(
    'initrd/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()],
  )
endforeach
