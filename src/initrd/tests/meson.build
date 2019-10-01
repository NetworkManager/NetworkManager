c_flags = test_c_flags + ['-DTEST_INITRD_DIR="@0@"'.format(meson.current_source_dir())]

test_units = [
  'test-dt-reader',
  'test-ibft-reader',
  'test-cmdline-reader',
]

foreach test_unit : test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: libnetwork_manager_test_dep,
    c_args: c_flags,
    link_with: libnmi_core,
  )

  test(
    'initrd/' + test_unit,
    test_script,
    timeout: default_test_timeout,
    args: test_args + [exe.full_path()],
  )
endforeach
